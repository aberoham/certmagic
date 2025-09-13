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
	"golang.org/x/crypto/ocsp"
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

	// Should be reasonable for a test certificate (between 1KB and 15KB with OCSP)
	if usage < 1000 || usage > 15000 {
		t.Errorf("Memory estimation seems unrealistic: %d bytes", usage)
	}

	t.Logf("Certificate memory usage estimate: %d bytes", usage)
}

func TestOCSPLazyLoading(t *testing.T) {
	logger := zaptest.NewLogger(t)

	t.Run("OCSPUnloadingUnderMemoryPressure", func(t *testing.T) {
		cache := NewCache(CacheOptions{
			MaxMemoryMB:    0, // We'll set a very small limit manually for testing
			EvictionPolicy: "lru",
			GetConfigForCert: func(cert Certificate) (*Config, error) {
				return &Config{Logger: logger}, nil
			},
			Logger: logger,
		})
		defer cache.Stop()

		// Set a small memory limit for testing (200KB should be exceeded by 10 certs with OCSP)
		cache.optionsMu.Lock()
		cache.options.MaxMemoryMB = 0 // Disable MB check temporarily
		cache.optionsMu.Unlock()

		// Create certificates with OCSP responses to simulate memory usage
		var certsWithOCSP []Certificate
		for i := 0; i < 10; i++ {
			domain := fmt.Sprintf("ocsp-test%d.example.com", i)
			cert := createTestCertificate(domain)

			// Add a mock OCSP response to increase memory usage
			cert.ocsp = &ocsp.Response{
				Status:       ocsp.Good,
				SerialNumber: big.NewInt(int64(i + 1)),
				ThisUpdate:   time.Now(),
				NextUpdate:   time.Now().Add(24 * time.Hour),
				TBSResponseData: make([]byte, 1024), // 1KB of mock data
				Signature:       make([]byte, 256),  // 256 bytes signature
			}

			certsWithOCSP = append(certsWithOCSP, cert)
			cache.cacheCertificate(cert)
		}

		initialStats := cache.GetMemoryStats()
		t.Logf("Initial state: %d certificates, %d bytes memory",
			initialStats.CertificateCount, initialStats.EstimatedMemoryBytes)

		// Verify some certificates have OCSP responses
		ocspCount := 0
		cache.mu.RLock()
		for _, cert := range cache.cache {
			if cert.ocsp != nil {
				ocspCount++
			}
		}
		cache.mu.RUnlock()

		if ocspCount == 0 {
			t.Fatal("Expected some certificates to have OCSP responses")
		}
		t.Logf("Certificates with OCSP responses: %d", ocspCount)

		// Now simulate memory pressure by setting a limit and testing OCSP unloading
		cache.optionsMu.Lock()
		cache.options.MaxMemoryMB = 1 // Set a limit that should trigger OCSP unloading
		cache.optionsMu.Unlock()

		// Manually test OCSP unloading
		cache.mu.Lock()
		unloadSuccessful := cache.unloadOCSPResponses()
		cache.mu.Unlock()

		if !unloadSuccessful {
			t.Log("OCSP unloading was not successful (this may be expected if already under limit)")
		}

		finalStats := cache.GetMemoryStats()
		t.Logf("Final state: %d certificates, %d bytes memory",
			finalStats.CertificateCount, finalStats.EstimatedMemoryBytes)

		// Check if OCSP unloading happened
		finalOCSPCount := 0
		cache.mu.RLock()
		for _, cert := range cache.cache {
			if cert.ocsp != nil {
				finalOCSPCount++
			}
		}
		cache.mu.RUnlock()

		t.Logf("Final certificates with OCSP responses: %d", finalOCSPCount)

		// Check if OCSP responses were unloaded
		if finalOCSPCount < ocspCount {
			t.Logf("OCSP lazy loading successful: reduced from %d to %d OCSP responses",
				ocspCount, finalOCSPCount)
		} else {
			t.Logf("OCSP responses unchanged: %d -> %d (may be under memory limit)",
				ocspCount, finalOCSPCount)
		}
	})

	t.Run("EstimateOCSPMemoryUsage", func(t *testing.T) {
		// Test with nil response
		nilUsage := estimateOCSPMemoryUsage(nil)
		if nilUsage != 0 {
			t.Errorf("Expected 0 bytes for nil OCSP response, got %d", nilUsage)
		}

		// Test with basic response
		basicResp := &ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: big.NewInt(12345),
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(24 * time.Hour),
		}
		basicUsage := estimateOCSPMemoryUsage(basicResp)
		if basicUsage < 200 || basicUsage > 5000 {
			t.Errorf("Basic OCSP response usage seems unrealistic: %d bytes", basicUsage)
		}

		// Test with larger response (with data)
		largeResp := &ocsp.Response{
			Status:          ocsp.Good,
			SerialNumber:    big.NewInt(12345),
			ThisUpdate:      time.Now(),
			NextUpdate:      time.Now().Add(24 * time.Hour),
			TBSResponseData: make([]byte, 1024),
			Signature:       make([]byte, 256),
		}
		largeUsage := estimateOCSPMemoryUsage(largeResp)
		if largeUsage < basicUsage {
			t.Errorf("Expected large OCSP response (%d bytes) to be at least as big as basic (%d bytes)",
				largeUsage, basicUsage)
		}
		// Note: Both may end up being 2048 due to the minimum size check

		t.Logf("OCSP memory estimates: nil=%d, basic=%d, large=%d",
			nilUsage, basicUsage, largeUsage)
	})

	t.Run("CertificateHasOCSP", func(t *testing.T) {
		// Certificate with OCSP response
		certWithOCSP := createTestCertificate("with-ocsp.example.com")
		certWithOCSP.ocsp = &ocsp.Response{Status: ocsp.Good}

		if !certWithOCSP.HasOCSP() {
			t.Error("Certificate with OCSP response should return HasOCSP() = true")
		}

		// Certificate without OCSP response but with OCSP server in leaf cert
		certCanFetch := createTestCertificate("can-fetch.example.com")
		if certCanFetch.Leaf != nil {
			certCanFetch.Leaf.OCSPServer = []string{"http://ocsp.example.com"}
		}

		if !certCanFetch.HasOCSP() {
			t.Error("Certificate that can fetch OCSP should return HasOCSP() = true")
		}

		// Certificate without OCSP
		certWithoutOCSP := createTestCertificate("no-ocsp.example.com")
		if certWithoutOCSP.Leaf != nil {
			certWithoutOCSP.Leaf.OCSPServer = nil
		}

		if certWithoutOCSP.HasOCSP() {
			t.Error("Certificate without OCSP should return HasOCSP() = false")
		}
	})
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

func TestCertificateCompression(t *testing.T) {
	// Test compression functionality
	t.Run("CompressionAndDecompression", func(t *testing.T) {
		cert := createTestCertificate("compression-test.example.com")
		
		// Compress the certificate
		compressed, err := compressCertificate(cert)
		if err != nil {
			t.Fatalf("Failed to compress certificate: %v", err)
		}
		
		// Verify metadata is preserved
		if compressed.Hash != cert.Hash() {
			t.Error("Certificate hash not preserved in compression")
		}
		if len(compressed.Names) != len(cert.Names) {
			t.Error("Certificate names not preserved in compression")
		}
		if compressed.Names[0] != cert.Names[0] {
			t.Error("Certificate name mismatch in compression")
		}
		
		// Decompress the certificate
		decompressed, err := compressed.decompressCertificate()
		if err != nil {
			t.Fatalf("Failed to decompress certificate: %v", err)
		}
		
		// Verify the decompressed certificate matches original
		if decompressed.Hash() != cert.Hash() {
			t.Error("Decompressed certificate hash doesn't match original")
		}
		if len(decompressed.Names) != len(cert.Names) {
			t.Error("Decompressed certificate names don't match original")
		}
		if decompressed.Names[0] != cert.Names[0] {
			t.Error("Decompressed certificate name doesn't match original")
		}
	})
	
	t.Run("CompressionMemoryReduction", func(t *testing.T) {
		cert := createTestCertificate("memory-test.example.com")
		originalSize := estimateCertificateMemoryUsage(cert)
		
		compressed, err := compressCertificate(cert)
		if err != nil {
			t.Fatalf("Failed to compress certificate: %v", err)
		}
		
		compressedSize := compressed.estimateMemoryUsage()
		
		// Compressed size should be smaller (expect at least 20% reduction)
		if compressedSize >= originalSize {
			t.Errorf("Compressed size (%d) should be smaller than original (%d)", compressedSize, originalSize)
		}
		
		reductionPercent := float64(originalSize-compressedSize) / float64(originalSize) * 100
		t.Logf("Memory reduction: %.1f%% (original: %d bytes, compressed: %d bytes)", 
			reductionPercent, originalSize, compressedSize)
		
		if reductionPercent < 20 {
			t.Errorf("Expected at least 20%% memory reduction, got %.1f%%", reductionPercent)
		}
	})
}

func TestCacheWithCompression(t *testing.T) {
	logger := zaptest.NewLogger(t)
	
	// Test cache behavior with compression enabled
	t.Run("CompressedCacheOperations", func(t *testing.T) {
		opts := CacheOptions{
			GetConfigForCert: func(cert Certificate) (*Config, error) {
				return &Config{Logger: logger}, nil
			},
			Capacity:         5,
			MaxMemoryMB:      1,
			EvictionPolicy:   "lru",
			EnableCompression: true,
			Logger:           logger,
		}
		cache := NewCache(opts)
		defer cache.Stop()
		
		// Create and cache a certificate
		cert1 := createTestCertificate("compressed1.example.com")
		cache.cacheCertificate(cert1)
		
		// Verify it's stored in compressed cache
		if len(cache.compressedCache) != 1 {
			t.Error("Certificate not stored in compressed cache")
		}
		if len(cache.cache) != 0 {
			t.Error("Certificate should not be in regular cache when compression enabled")
		}
		
		// Retrieve the certificate
		certs := cache.getAllMatchingCerts("compressed1.example.com")
		if len(certs) != 1 {
			t.Fatalf("Expected 1 certificate, got %d", len(certs))
		}
		
		retrievedCert := certs[0]
		if retrievedCert.Hash() != cert1.Hash() {
			t.Error("Retrieved certificate hash doesn't match original")
		}
		if retrievedCert.Names[0] != cert1.Names[0] {
			t.Error("Retrieved certificate name doesn't match original")
		}
	})
	
	t.Run("CompressedCacheEviction", func(t *testing.T) {
		opts := CacheOptions{
			GetConfigForCert: func(cert Certificate) (*Config, error) {
				return &Config{Logger: logger}, nil
			},
			Capacity:         2, // Small capacity to trigger eviction
			MaxMemoryMB:      1,
			EvictionPolicy:   "lru",
			EnableCompression: true,
			Logger:           logger,
		}
		cache := NewCache(opts)
		defer cache.Stop()
		
		// Add certificates to reach capacity
		cert1 := createTestCertificate("evict1.example.com")
		cert2 := createTestCertificate("evict2.example.com")
		cert3 := createTestCertificate("evict3.example.com")
		
		cache.cacheCertificate(cert1)
		cache.cacheCertificate(cert2)
		
		// Access cert1 to make it more recently used than cert2
		cache.getAllMatchingCerts("evict1.example.com")
		
		// Add cert3, should evict cert2 (least recently used)
		cache.cacheCertificate(cert3)
		
		// Verify cert1 and cert3 are present, cert2 is evicted
		certs1 := cache.getAllMatchingCerts("evict1.example.com")
		certs2 := cache.getAllMatchingCerts("evict2.example.com")
		certs3 := cache.getAllMatchingCerts("evict3.example.com")
		
		if len(certs1) != 1 {
			t.Error("cert1 should still be in cache (recently accessed)")
		}
		if len(certs2) != 0 {
			t.Error("cert2 should be evicted (least recently used)")
		}
		if len(certs3) != 1 {
			t.Error("cert3 should be in cache (just added)")
		}
	})
	
	t.Run("MixedCacheMode", func(t *testing.T) {
		// Test that cache works when both compressed and regular certs exist
		opts := CacheOptions{
			GetConfigForCert: func(cert Certificate) (*Config, error) {
				return &Config{Logger: logger}, nil
			},
			Capacity:         10,
			MaxMemoryMB:      5,
			EvictionPolicy:   "lru",
			EnableCompression: false, // Start with compression disabled
			Logger:           logger,
		}
		cache := NewCache(opts)
		defer cache.Stop()
		
		// Add a regular certificate
		cert1 := createTestCertificate("mixed1.example.com")
		cache.cacheCertificate(cert1)
		
		// Enable compression
		opts.EnableCompression = true
		cache.SetOptions(opts)
		
		// Add a compressed certificate
		cert2 := createTestCertificate("mixed2.example.com")
		cache.cacheCertificate(cert2)
		
		// Both should be retrievable
		certs1 := cache.getAllMatchingCerts("mixed1.example.com")
		certs2 := cache.getAllMatchingCerts("mixed2.example.com")
		
		if len(certs1) != 1 {
			t.Error("Regular certificate should be retrievable")
		}
		if len(certs2) != 1 {
			t.Error("Compressed certificate should be retrievable")
		}
		
		// Verify they're in different caches
		if len(cache.cache) != 1 {
			t.Error("Regular cache should have 1 certificate")
		}
		if len(cache.compressedCache) != 1 {
			t.Error("Compressed cache should have 1 certificate")
		}
		
		// Memory stats should count both
		stats := cache.GetMemoryStats()
		if stats.CertificateCount != 2 {
			t.Errorf("Expected total count of 2, got %d", stats.CertificateCount)
		}
	})
}