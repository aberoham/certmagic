// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// createTestCertificate creates a test certificate for the given domain
func createTestCertificate(domain string) Certificate {
	// Create a simple test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{domain},
	}

	// Create private key
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create certificate
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)

	// Create tls.Certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	// Parse leaf certificate
	tlsCert.Leaf, _ = x509.ParseCertificate(certDER)

	// Create Certificate struct with some test data
	cert := Certificate{
		Certificate: tlsCert,
		Names:       []string{domain},
		Tags:        []string{"test", "memory"},
		managed:     true,
		issuerKey:   "test-issuer",
	}

	// Calculate hash
	cert.hash = hashCertificateChain(tlsCert.Certificate)

	return cert
}

func TestCacheMemoryLimits(t *testing.T) {
	logger := zaptest.NewLogger(t)

	t.Run("MemoryLimitEviction", func(t *testing.T) {
		// Use a very small limit to trigger eviction quickly 
		// Each cert is ~11KB so 1MB should hold about 90 certs, but we'll trigger earlier due to overhead
		maxMemoryMB := 1
		cache := NewCache(CacheOptions{
			MaxMemoryMB:    maxMemoryMB,
			EvictionPolicy: "lru",
			GetConfigForCert: func(cert Certificate) (*Config, error) {
				return &Config{Logger: logger}, nil
			},
			Logger: logger,
		})
		defer cache.Stop()
		
		maxBytes := int64(maxMemoryMB * 1024 * 1024) // 1MB
		
		// Add certificates until we trigger eviction
		numAdded := 0
		maxCerts := 100 // Try to add up to 100 certificates 
		beforeEvictionCount := 0
		
		for i := 0; i < maxCerts; i++ {
			domain := fmt.Sprintf("test%d.example.com", i)
			cert := createTestCertificate(domain)

			cache.cacheCertificate(cert)
			numAdded++

			stats := cache.GetMemoryStats()
			if stats.EstimatedMemoryBytes > maxBytes {
				if beforeEvictionCount == 0 {
					beforeEvictionCount = stats.CertificateCount
					t.Logf("Memory usage %d bytes exceeded %d bytes limit at %d certificates", 
						stats.EstimatedMemoryBytes, maxBytes, stats.CertificateCount)
				}
				
				// Add a few more to ensure eviction kicks in
				if i >= beforeEvictionCount + 5 {
					break
				}
			}
		}

		finalStats := cache.GetMemoryStats()
		
		// We should have triggered eviction based on memory limit
		if beforeEvictionCount == 0 {
			t.Error("Expected to exceed memory limit and trigger eviction, but never did")
		}
		
		// When memory eviction is active, we should have fewer certs than we tried to add
		// but the count should stabilize (not continuously decrease)
		if finalStats.CertificateCount >= numAdded {
			t.Errorf("Expected eviction to limit certificate count, but have %d out of %d added", 
				finalStats.CertificateCount, numAdded)
		}
		
		// Memory usage should be around the limit (may slightly exceed due to timing)
		maxAllowedBytes := maxBytes * 110 / 100 // Allow 10% overage
		if finalStats.EstimatedMemoryBytes > maxAllowedBytes {
			t.Errorf("Memory usage %d bytes significantly exceeds limit of %d bytes", 
				finalStats.EstimatedMemoryBytes, maxBytes)
		}
		
		t.Logf("Final: %d certificates (added %d), %d bytes memory", 
			finalStats.CertificateCount, numAdded, finalStats.EstimatedMemoryBytes)
	})

	t.Run("LRUEviction", func(t *testing.T) {
		// Create cache with small capacity
		cache := NewCache(CacheOptions{
			Capacity:       3,
			EvictionPolicy: "lru",
			GetConfigForCert: func(cert Certificate) (*Config, error) {
				return &Config{Logger: logger}, nil
			},
			Logger: logger,
		})
		defer cache.Stop()

		// Add 4 certificates (should evict the first one)
		cert1 := createTestCertificate("test1.example.com")
		cert2 := createTestCertificate("test2.example.com")
		cert3 := createTestCertificate("test3.example.com")
		cert4 := createTestCertificate("test4.example.com")

		cache.cacheCertificate(cert1)
		cache.cacheCertificate(cert2)
		cache.cacheCertificate(cert3)

		// Access cert1 to make it recently used
		cache.getAllMatchingCerts("test1.example.com")

		// Add cert4 - should evict cert2 (least recently used)
		cache.cacheCertificate(cert4)

		// Verify cert2 was evicted but cert1 is still there
		certs1 := cache.getAllMatchingCerts("test1.example.com")
		certs2 := cache.getAllMatchingCerts("test2.example.com")
		certs4 := cache.getAllMatchingCerts("test4.example.com")

		if len(certs1) == 0 {
			t.Error("Expected cert1 to still be in cache (was recently accessed)")
		}
		if len(certs2) != 0 {
			t.Error("Expected cert2 to be evicted (least recently used)")
		}
		if len(certs4) == 0 {
			t.Error("Expected cert4 to be in cache (just added)")
		}

		stats := cache.GetMemoryStats()
		if stats.CertificateCount != 3 {
			t.Errorf("Expected exactly 3 certificates in cache, got %d", stats.CertificateCount)
		}
	})

	t.Run("RandomEviction", func(t *testing.T) {
		// Create cache with random eviction policy
		cache := NewCache(CacheOptions{
			Capacity:       2,
			EvictionPolicy: "random",
			GetConfigForCert: func(cert Certificate) (*Config, error) {
				return &Config{Logger: logger}, nil
			},
			Logger: logger,
		})
		defer cache.Stop()

		// Add 3 certificates
		cert1 := createTestCertificate("test1.example.com")
		cert2 := createTestCertificate("test2.example.com")
		cert3 := createTestCertificate("test3.example.com")

		cache.cacheCertificate(cert1)
		cache.cacheCertificate(cert2)
		cache.cacheCertificate(cert3)

		// Should have only 2 certificates
		stats := cache.GetMemoryStats()
		if stats.CertificateCount != 2 {
			t.Errorf("Expected exactly 2 certificates in cache with random eviction, got %d", stats.CertificateCount)
		}
	})

	t.Run("MemoryStatsAccuracy", func(t *testing.T) {
		cache := NewCache(CacheOptions{
			GetConfigForCert: func(cert Certificate) (*Config, error) {
				return &Config{Logger: logger}, nil
			},
			Logger: logger,
		})
		defer cache.Stop()

		// Start with empty cache
		stats := cache.GetMemoryStats()
		if stats.CertificateCount != 0 || stats.EstimatedMemoryBytes != 0 {
			t.Errorf("Expected empty cache, got %d certs, %d bytes", stats.CertificateCount, stats.EstimatedMemoryBytes)
		}

		// Add one certificate
		cert := createTestCertificate("test.example.com")
		cache.cacheCertificate(cert)

		stats = cache.GetMemoryStats()
		if stats.CertificateCount != 1 {
			t.Errorf("Expected 1 certificate, got %d", stats.CertificateCount)
		}
		if stats.EstimatedMemoryBytes <= 0 {
			t.Errorf("Expected positive memory usage, got %d bytes", stats.EstimatedMemoryBytes)
		}

		expectedUsage := estimateCertificateMemoryUsage(cert)
		if stats.EstimatedMemoryBytes != expectedUsage {
			t.Errorf("Expected memory usage %d bytes, got %d bytes", expectedUsage, stats.EstimatedMemoryBytes)
		}

		// Remove certificate manually and verify memory is freed
		cache.mu.Lock()
		cache.removeCertificate(cert.hash)
		cache.mu.Unlock()

		stats = cache.GetMemoryStats()
		if stats.CertificateCount != 0 || stats.EstimatedMemoryBytes != 0 {
			t.Errorf("Expected empty cache after removal, got %d certs, %d bytes", stats.CertificateCount, stats.EstimatedMemoryBytes)
		}
	})
}

func TestConcurrentCacheOperations(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cache := NewCache(CacheOptions{
		MaxMemoryMB:    5,
		Capacity:       50,
		EvictionPolicy: "lru",
		GetConfigForCert: func(cert Certificate) (*Config, error) {
			return &Config{Logger: logger}, nil
		},
		Logger: logger,
	})
	defer cache.Stop()

	// Run concurrent operations
	var wg sync.WaitGroup
	numWorkers := 10
	certsPerWorker := 10

	// Concurrent additions
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < certsPerWorker; j++ {
				domain := fmt.Sprintf("worker%d-test%d.example.com", workerID, j)
				cert := createTestCertificate(domain)
				cache.cacheCertificate(cert)
			}
		}(i)
	}

	// Concurrent reads
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < certsPerWorker; j++ {
				domain := fmt.Sprintf("worker%d-test%d.example.com", workerID, j)
				cache.getAllMatchingCerts(domain)
				// Add some delay to make the test more realistic
				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	wg.Wait()

	// Verify cache is still functional
	stats := cache.GetMemoryStats()
	if stats.CertificateCount <= 0 {
		t.Error("Expected certificates in cache after concurrent operations")
	}
	if stats.EstimatedMemoryBytes <= 0 {
		t.Error("Expected positive memory usage after concurrent operations")
	}

	t.Logf("Final state after concurrent operations: %d certificates, %dMB estimated memory", 
		stats.CertificateCount, stats.EstimatedMemoryMB)

	// Verify we stayed within limits
	if stats.EstimatedMemoryMB > 5 {
		t.Errorf("Memory usage %dMB exceeded limit of 5MB", stats.EstimatedMemoryMB)
	}
	if stats.CertificateCount > 50 {
		t.Errorf("Certificate count %d exceeded capacity of 50", stats.CertificateCount)
	}
}

func TestMemoryEstimation(t *testing.T) {
	cert := createTestCertificate("test.example.com")

	// Add some extra data to make estimation more realistic
	cert.Tags = []string{"tag1", "tag2", "tag3"}
	
	usage := estimateCertificateMemoryUsage(cert)

	if usage <= 0 {
		t.Error("Expected positive memory usage estimation")
	}

	// Should be reasonable for a test certificate (between 1KB and 10KB)
	if usage < 1000 || usage > 10000 {
		t.Errorf("Memory estimation seems unrealistic: %d bytes", usage)
	}

	t.Logf("Certificate memory usage estimate: %d bytes", usage)
}

func BenchmarkCacheOperations(b *testing.B) {
	logger := zaptest.NewLogger(b)

	cache := NewCache(CacheOptions{
		MaxMemoryMB:    10,
		EvictionPolicy: "lru",
		GetConfigForCert: func(cert Certificate) (*Config, error) {
			return &Config{Logger: logger}, nil
		},
		Logger: logger,
	})
	defer cache.Stop()

	// Pre-populate cache with test certificates
	var testCerts []Certificate
	for i := 0; i < 100; i++ {
		domain := fmt.Sprintf("bench-test%d.example.com", i)
		cert := createTestCertificate(domain)
		testCerts = append(testCerts, cert)
		cache.cacheCertificate(cert)
	}

	b.ResetTimer()

	b.Run("CacheCertificate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cert := testCerts[i%len(testCerts)]
			cert.hash = fmt.Sprintf("bench-%d-%s", i, cert.hash) // Make unique
			cache.cacheCertificate(cert)
		}
	})

	b.Run("GetMatchingCerts", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			domain := fmt.Sprintf("bench-test%d.example.com", i%100)
			cache.getAllMatchingCerts(domain)
		}
	})

	b.Run("MemoryStats", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cache.GetMemoryStats()
		}
	})
}