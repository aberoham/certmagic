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
	"container/list"
	"fmt"
	weakrand "math/rand"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
)

// Cache is a structure that stores certificates in memory.
// A Cache indexes certificates by name for quick access
// during TLS handshakes, and avoids duplicating certificates
// in memory. Generally, there should only be one per process.
// However, that is not a strict requirement; but using more
// than one is a code smell, and may indicate an
// over-engineered design.
//
// An empty cache is INVALID and must not be used. Be sure
// to call NewCache to get a valid value.
//
// These should be very long-lived values and must not be
// copied. Before all references leave scope to be garbage
// collected, ensure you call Stop() to stop maintenance on
// the certificates stored in this cache and release locks.
//
// Caches are not usually manipulated directly; create a
// Config value with a pointer to a Cache, and then use
// the Config to interact with the cache. Caches are
// agnostic of any particular storage or ACME config,
// since each certificate may be managed and stored
// differently.
type Cache struct {
	// User configuration of the cache
	options   CacheOptions
	optionsMu sync.RWMutex

	// The cache is keyed by certificate hash
	cache map[string]Certificate

	// cacheIndex is a map of SAN to cache key (cert hash)
	cacheIndex map[string][]string

	// Memory usage tracking
	currentMemoryBytes int64

	// LRU tracking for memory-aware eviction
	lruList *list.List
	lruMap  map[string]*list.Element

	// Protects the cache and cacheIndex maps
	mu sync.RWMutex

	// Close this channel to cancel asset maintenance
	stopChan chan struct{}

	// Used to signal when stopping is completed
	doneChan chan struct{}

	logger *zap.Logger
}

// MemoryStats holds memory usage information for the cache
type MemoryStats struct {
	CertificateCount       int   `json:"certificate_count"`
	EstimatedMemoryBytes   int64 `json:"estimated_memory_bytes"`
	EstimatedMemoryMB      int   `json:"estimated_memory_mb"`
	RuntimeHeapBytes       int64 `json:"runtime_heap_bytes"`
	RuntimeHeapMB          int   `json:"runtime_heap_mb"`
	LastGC                 int64 `json:"last_gc_ns"`
	GCCount                int   `json:"gc_count"`
}

// GetMemoryStats returns current memory usage statistics for the cache
func (certCache *Cache) GetMemoryStats() MemoryStats {
	certCache.mu.RLock()
	defer certCache.mu.RUnlock()

	// Get runtime memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return MemoryStats{
		CertificateCount:     len(certCache.cache),
		EstimatedMemoryBytes: certCache.currentMemoryBytes,
		EstimatedMemoryMB:    int(certCache.currentMemoryBytes / (1024 * 1024)),
		RuntimeHeapBytes:     int64(m.HeapAlloc),
		RuntimeHeapMB:        int(m.HeapAlloc / (1024 * 1024)),
		LastGC:               int64(m.LastGC),
		GCCount:              int(m.NumGC),
	}
}

// LogMemoryStats logs current memory usage statistics
func (certCache *Cache) LogMemoryStats() {
	stats := certCache.GetMemoryStats()

	certCache.optionsMu.RLock()
	maxMemoryMB := certCache.options.MaxMemoryMB
	capacity := certCache.options.Capacity
	certCache.optionsMu.RUnlock()
	certCache.logger.Info("cache memory statistics",
		zap.Int("certificate_count", stats.CertificateCount),
		zap.Int("estimated_memory_mb", stats.EstimatedMemoryMB),
		zap.Int("runtime_heap_mb", stats.RuntimeHeapMB),
		zap.Int("max_memory_mb", maxMemoryMB),
		zap.Int("capacity", capacity),
		zap.Int("gc_count", stats.GCCount))
}

// startMemoryMonitor starts a goroutine that periodically checks memory usage
// and triggers garbage collection if memory pressure is high
func (certCache *Cache) startMemoryMonitor(interval time.Duration) {
	if interval <= 0 {
		return // Memory monitoring disabled
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Get current memory usage
				var m runtime.MemStats
				runtime.ReadMemStats(&m)

				// Log stats periodically (every 10 checks)
				checkCount := int(time.Now().Unix()/int64(interval.Seconds())) % 10
				if checkCount == 0 {
					certCache.LogMemoryStats()
				}

				// Check if we should force garbage collection
				// (when heap usage is high or memory pressure detected)
				heapMB := int64(m.HeapAlloc / (1024 * 1024))

				certCache.optionsMu.RLock()
				maxMemoryMB := int64(certCache.options.MaxMemoryMB)
				certCache.optionsMu.RUnlock()

				// Force GC if heap usage is 80% of our limit or if we're over our limit
				shouldForceGC := false
				if maxMemoryMB > 0 {
					shouldForceGC = heapMB >= (maxMemoryMB*8/10) || certCache.isAtMemoryLimit()
				} else {
					// If no limit set, force GC when heap gets very large (>1GB)
					shouldForceGC = heapMB > 1024
				}

				if shouldForceGC {
					certCache.logger.Debug("forcing garbage collection due to memory pressure",
						zap.Int64("heap_mb", heapMB),
						zap.Int64("max_memory_mb", maxMemoryMB))
					runtime.GC()
				}
			case <-certCache.stopChan:
				return
			}
		}
	}()
}

// NewCache returns a new, valid Cache for efficiently
// accessing certificates in memory. It also begins a
// maintenance goroutine to tend to the certificates
// in the cache. Call Stop() when you are done with the
// cache so it can clean up locks and stuff.
//
// Most users of this package will not need to call this
// because a default certificate cache is created for you.
// Only advanced use cases require creating a new cache.
//
// This function panics if opts.GetConfigForCert is not
// set. The reason is that a cache absolutely needs to
// be able to get a Config with which to manage TLS
// assets, and it is not safe to assume that the Default
// config is always the correct one, since you have
// created the cache yourself.
//
// See the godoc for Cache to use it properly. When
// no longer needed, caches should be stopped with
// Stop() to clean up resources even if the process
// is being terminated, so that it can clean up
// any locks for other processes to unblock!
func NewCache(opts CacheOptions) *Cache {
	c := &Cache{
		cache:              make(map[string]Certificate),
		cacheIndex:         make(map[string][]string),
		currentMemoryBytes: 0,
		lruList:            list.New(),
		lruMap:             make(map[string]*list.Element),
		stopChan:           make(chan struct{}),
		doneChan:           make(chan struct{}),
		logger:             opts.Logger,
	}

	// absolutely do not allow a nil logger; panics galore
	if c.logger == nil {
		c.logger = defaultLogger
	}

	c.SetOptions(opts)

	go c.maintainAssets(0)

	// Start memory monitoring (every 30 seconds by default)
	c.startMemoryMonitor(30 * time.Second)

	return c
}

func (certCache *Cache) SetOptions(opts CacheOptions) {
	// assume default options if necessary
	if opts.OCSPCheckInterval <= 0 {
		opts.OCSPCheckInterval = DefaultOCSPCheckInterval
	}
	if opts.RenewCheckInterval <= 0 {
		opts.RenewCheckInterval = DefaultRenewCheckInterval
	}
	if opts.Capacity < 0 {
		opts.Capacity = 0
	}
	if opts.MaxMemoryMB < 0 {
		opts.MaxMemoryMB = 0
	}
	if opts.EvictionPolicy == "" {
		opts.EvictionPolicy = "lru"
	}

	// this must be set, because we cannot not
	// safely assume that the Default Config
	// is always the correct one to use
	if opts.GetConfigForCert == nil {
		panic("cache must be initialized with a GetConfigForCert callback")
	}

	certCache.optionsMu.Lock()
	certCache.options = opts
	certCache.optionsMu.Unlock()
}

// Stop stops the maintenance goroutine for
// certificates in certCache. It blocks until
// stopping is complete. Once a cache is
// stopped, it cannot be reused.
func (certCache *Cache) Stop() {
	close(certCache.stopChan) // signal to stop
	<-certCache.doneChan      // wait for stop to complete
}

// CacheOptions is used to configure certificate caches.
// Once a cache has been created with certain options,
// those settings cannot be changed.
type CacheOptions struct {
	// REQUIRED. A function that returns a configuration
	// used for managing a certificate, or for accessing
	// that certificate's asset storage (e.g. for
	// OCSP staples, etc). The returned Config MUST
	// be associated with the same Cache as the caller,
	// use New to obtain a valid Config.
	//
	// The reason this is a callback function, dynamically
	// returning a Config (instead of attaching a static
	// pointer to a Config on each certificate) is because
	// the config for how to manage a domain's certificate
	// might change from maintenance to maintenance. The
	// cache is so long-lived, we cannot assume that the
	// host's situation will always be the same; e.g. the
	// certificate might switch DNS providers, so the DNS
	// challenge (if used) would need to be adjusted from
	// the last time it was run ~8 weeks ago.
	GetConfigForCert ConfigGetter

	// How often to check certificates for renewal;
	// if unset, DefaultOCSPCheckInterval will be used.
	OCSPCheckInterval time.Duration

	// How often to check certificates for renewal;
	// if unset, DefaultRenewCheckInterval will be used.
	RenewCheckInterval time.Duration

	// Maximum number of certificates to allow in the cache.
	// If reached, certificates will be evicted according to
	// EvictionPolicy to make room for new ones. 0 means unlimited.
	Capacity int

	// Maximum memory usage in MB for certificate cache.
	// If reached, certificates will be evicted according to
	// EvictionPolicy. 0 means unlimited. Takes precedence over Capacity.
	MaxMemoryMB int

	// Eviction policy when cache limits are reached.
	// "lru" (default) for Least Recently Used, "random" for random eviction.
	EvictionPolicy string

	// Set a logger to enable logging
	Logger *zap.Logger
}

// ConfigGetter is a function that returns a prepared,
// valid config that should be used when managing the
// given certificate or its assets.
type ConfigGetter func(Certificate) (*Config, error)

// estimateCertificateMemoryUsage returns an estimate of the memory
// usage of a certificate in bytes, including all associated data.
func estimateCertificateMemoryUsage(cert Certificate) int64 {
	var total int64

	// tls.Certificate struct overhead and DER data
	for _, certDER := range cert.Certificate.Certificate {
		total += int64(len(certDER))
	}
	if cert.Certificate.PrivateKey != nil {
		total += 2048 // Estimate for private key
	}

	// Add significant overhead for Go data structures
	// Real certificates in production have much more overhead due to
	// Go runtime structures, alignment, etc.
	total += 8192 // Base overhead per certificate

	// Names slice
	for _, name := range cert.Names {
		total += int64(len(name)) + 16 // string overhead
	}

	// Tags slice
	for _, tag := range cert.Tags {
		total += int64(len(tag)) + 16 // string overhead
	}

	// OCSP response (if present) - this is where we can save memory
	if cert.ocsp != nil {
		total += estimateOCSPMemoryUsage(cert.ocsp)
	}

	// Other string fields
	total += int64(len(cert.hash)) + 16
	total += int64(len(cert.issuerKey)) + 16

	// Struct overhead and alignment
	total += 200

	return total
}

// estimateOCSPMemoryUsage estimates the memory usage of an OCSP response
func estimateOCSPMemoryUsage(resp *ocsp.Response) int64 {
	if resp == nil {
		return 0
	}

	// Basic OCSP response structure
	size := int64(200) // Base struct size

	// Add size for variable fields
	if len(resp.TBSResponseData) > 0 {
		size += int64(len(resp.TBSResponseData))
	}
	if len(resp.Signature) > 0 {
		size += int64(len(resp.Signature))
	}

	// Certificate in response (if any)
	if resp.Certificate != nil && len(resp.Certificate.Raw) > 0 {
		size += int64(len(resp.Certificate.Raw))
	}

	// Extensions
	for _, ext := range resp.Extensions {
		size += int64(len(ext.Value)) + 50 // OID overhead
	}

	// Use a conservative minimum estimate
	if size < 1500 {
		size = 2048 // Typical OCSP response size
	}

	return size
}

// updateLRU updates the LRU tracking for a certificate.
// Must be called with write lock held.
func (certCache *Cache) updateLRU(certHash string) {
	// Skip LRU tracking if not properly initialized (e.g., in tests)
	if certCache.lruList == nil || certCache.lruMap == nil {
		return
	}

	if element, exists := certCache.lruMap[certHash]; exists {
		certCache.lruList.MoveToFront(element)
	} else {
		element := certCache.lruList.PushFront(certHash)
		certCache.lruMap[certHash] = element
	}
}

// evictLRU removes the least recently used certificate.
// Must be called with write lock held.
func (certCache *Cache) evictLRU() {
	// Skip LRU eviction if not properly initialized (e.g., in tests)
	if certCache.lruList == nil || certCache.lruMap == nil {
		return
	}

	if certCache.lruList.Len() == 0 {
		return
	}

	element := certCache.lruList.Back()
	if element != nil {
		certHash := element.Value.(string)
		certCache.removeCertificate(certHash)
	}
}

// evictRandom removes a random certificate (legacy behavior).
// Must be called with write lock held.
func (certCache *Cache) evictRandom() {
	cacheSize := len(certCache.cache)
	if cacheSize == 0 {
		return
	}

	rnd := weakrand.Intn(cacheSize)
	i := 0
	for _, randomCert := range certCache.cache {
		if i == rnd {
			certCache.removeCertificate(randomCert.hash)
			break
		}
		i++
	}
}

// removeCertificate removes a certificate from cache, index, memory tracking, and LRU.
// Must be called with write lock held.
func (certCache *Cache) removeCertificate(certHash string) {
	cert, exists := certCache.cache[certHash]
	if !exists {
		return
	}

	// Remove from main cache
	delete(certCache.cache, certHash)

	// Remove from index
	for _, name := range cert.Names {
		if hashes, exists := certCache.cacheIndex[name]; exists {
			for i, hash := range hashes {
				if hash == certHash {
					certCache.cacheIndex[name] = append(hashes[:i], hashes[i+1:]...)
					break
				}
			}
			// Clean up empty index entries
			if len(certCache.cacheIndex[name]) == 0 {
				delete(certCache.cacheIndex, name)
			}
		}
	}

	// Remove from LRU tracking (if initialized)
	if certCache.lruList != nil && certCache.lruMap != nil {
		if element, exists := certCache.lruMap[certHash]; exists {
			certCache.lruList.Remove(element)
			delete(certCache.lruMap, certHash)
		}
	}

	// Update memory usage
	certCache.currentMemoryBytes -= estimateCertificateMemoryUsage(cert)
	if certCache.currentMemoryBytes < 0 {
		certCache.currentMemoryBytes = 0
	}

	certCache.logger.Debug("evicted certificate from cache",
		zap.Strings("names", cert.Names),
		zap.String("hash", certHash),
		zap.Int64("memory_bytes", certCache.currentMemoryBytes))
}

// isAtMemoryLimit checks if the cache is at or over the memory limit.
// Must be called with read lock held.
func (certCache *Cache) isAtMemoryLimit() bool {
	certCache.optionsMu.RLock()
	maxMemoryMB := certCache.options.MaxMemoryMB
	certCache.optionsMu.RUnlock()

	if maxMemoryMB <= 0 {
		return false // No memory limit set
	}

	maxMemoryBytes := int64(maxMemoryMB) * 1024 * 1024
	return certCache.currentMemoryBytes >= maxMemoryBytes
}

// isAtCapacityLimit checks if the cache is at or over the capacity limit.
// Must be called with read lock held.
func (certCache *Cache) isAtCapacityLimit() bool {
	certCache.optionsMu.RLock()
	capacity := certCache.options.Capacity
	certCache.optionsMu.RUnlock()

	if capacity <= 0 {
		return false // No capacity limit set
	}

	return len(certCache.cache) >= capacity
}

// shouldEvict determines if certificates should be evicted to make room.
// Must be called with read lock held.
func (certCache *Cache) shouldEvict() bool {
	return certCache.isAtMemoryLimit() || certCache.isAtCapacityLimit()
}

// performEviction evicts certificates according to the configured policy.
// If memory pressure is high, it first tries to unload OCSP responses
// before removing entire certificates.
// Must be called with write lock held.
func (certCache *Cache) performEviction() {
	certCache.optionsMu.RLock()
	evictionPolicy := certCache.options.EvictionPolicy
	certCache.optionsMu.RUnlock()

	// First try OCSP unloading if we're under memory pressure
	if certCache.isAtMemoryLimit() && !certCache.isAtCapacityLimit() {
		if certCache.unloadOCSPResponses() {
			return // OCSP unloading was successful
		}
	}

	// If OCSP unloading wasn't enough, evict certificates
	if evictionPolicy == "random" {
		certCache.evictRandom()
	} else {
		certCache.evictLRU() // Default to LRU
	}
}

// unloadOCSPResponses unloads OCSP responses from certificates to save memory.
// Returns true if it successfully freed enough memory to get under the limit.
// Must be called with write lock held.
func (certCache *Cache) unloadOCSPResponses() bool {
	if len(certCache.cache) == 0 {
		return false
	}

	var freedBytes int64
	var certsProcessed int

	// Target: free enough memory to get 10% below the limit
	certCache.optionsMu.RLock()
	maxMemoryMB := certCache.options.MaxMemoryMB
	certCache.optionsMu.RUnlock()

	if maxMemoryMB <= 0 {
		return false
	}

	targetBytes := int64(maxMemoryMB) * 1024 * 1024 * 90 / 100 // 90% of limit
	needToFree := certCache.currentMemoryBytes - targetBytes

	if needToFree <= 0 {
		return true // Already under target
	}

	// Sort certificates by LRU order (least recently used first)
	sortedHashes := certCache.getSortedLRUHashes()

	for _, certHash := range sortedHashes {
		cert, exists := certCache.cache[certHash]
		if !exists || cert.ocsp == nil {
			continue
		}

		// Calculate memory that would be freed
		ocspMemory := estimateOCSPMemoryUsage(cert.ocsp)

		// Unload the OCSP response
		cert.ocsp = nil
		certCache.cache[certHash] = cert
		freedBytes += ocspMemory
		certsProcessed++

		certCache.logger.Debug("unloaded OCSP response to save memory",
			zap.Strings("cert_names", cert.Names),
			zap.String("cert_hash", certHash),
			zap.Int64("freed_bytes", ocspMemory))

		if freedBytes >= needToFree {
			break
		}

		// Don't process too many certificates at once
		if certsProcessed >= 50 {
			break
		}
	}

	// Update memory tracking
	certCache.currentMemoryBytes -= freedBytes

	certCache.logger.Info("OCSP lazy loading: unloaded responses to save memory",
		zap.Int("certificates_processed", certsProcessed),
		zap.Int64("memory_freed_bytes", freedBytes),
		zap.Int64("current_memory_bytes", certCache.currentMemoryBytes))

	return certCache.currentMemoryBytes < targetBytes
}

// getSortedLRUHashes returns certificate hashes sorted by LRU order (least recently used first)
func (certCache *Cache) getSortedLRUHashes() []string {
	if certCache.lruList == nil {
		// Fallback: just return all hashes
		hashes := make([]string, 0, len(certCache.cache))
		for hash := range certCache.cache {
			hashes = append(hashes, hash)
		}
		return hashes
	}

	hashes := make([]string, 0, certCache.lruList.Len())
	for e := certCache.lruList.Back(); e != nil; e = e.Prev() {
		if certHash, ok := e.Value.(string); ok {
			hashes = append(hashes, certHash)
		}
	}
	return hashes
}

// cacheCertificate calls unsyncedCacheCertificate with a write lock.
//
// This function is safe for concurrent use.
func (certCache *Cache) cacheCertificate(cert Certificate) {
	certCache.mu.Lock()
	certCache.unsyncedCacheCertificate(cert)
	certCache.mu.Unlock()
}

// unsyncedCacheCertificate adds cert to the in-memory cache unless
// it already exists in the cache (according to cert.Hash). It
// updates the name index and handles memory-aware eviction.
//
// This function is NOT safe for concurrent use. Callers MUST acquire
// a write lock on certCache.mu first.
func (certCache *Cache) unsyncedCacheCertificate(cert Certificate) {
	// if this certificate already exists in the cache, this is basically
	// a no-op so we reuse existing cert (prevent duplication), but we do
	// modify the cert to add tags it may be missing (see issue #211)
	if existingCert, ok := certCache.cache[cert.hash]; ok {
		logMsg := "certificate already cached"

		if len(cert.Tags) > 0 {
			for _, tag := range cert.Tags {
				if !existingCert.HasTag(tag) {
					existingCert.Tags = append(existingCert.Tags, tag)
				}
			}
			certCache.cache[cert.hash] = existingCert
			logMsg += "; appended any missing tags to cert"
		}

		// Update LRU since certificate was accessed
		certCache.updateLRU(cert.hash)

		certCache.logger.Debug(logMsg,
			zap.Strings("subjects", cert.Names),
			zap.Time("expiration", expiresAt(cert.Leaf)),
			zap.Bool("managed", cert.managed),
			zap.String("issuer_key", cert.issuerKey),
			zap.String("hash", cert.hash),
			zap.Strings("tags", cert.Tags))
		return
	}

	// Evict certificates if at capacity or memory limit
	for certCache.shouldEvict() {
		certCache.logger.Debug("cache at limit; performing eviction",
			zap.Strings("inserting_subjects", cert.Names),
			zap.String("inserting_hash", cert.hash),
			zap.Int("cache_size", len(certCache.cache)),
			zap.Int64("memory_bytes", certCache.currentMemoryBytes))
		certCache.performEviction()

		// Safety check to prevent infinite loop
		if len(certCache.cache) == 0 {
			break
		}
	}

	// Calculate memory usage for this certificate
	certMemoryUsage := estimateCertificateMemoryUsage(cert)

	// Store the certificate
	certCache.cache[cert.hash] = cert

	// Update memory tracking
	certCache.currentMemoryBytes += certMemoryUsage

	// Update LRU tracking
	certCache.updateLRU(cert.hash)

	// Update the index so we can access it by name
	for _, name := range cert.Names {
		certCache.cacheIndex[name] = append(certCache.cacheIndex[name], cert.hash)
	}

	certCache.optionsMu.RLock()
	certCache.logger.Debug("added certificate to cache",
		zap.Strings("subjects", cert.Names),
		zap.Time("expiration", expiresAt(cert.Leaf)),
		zap.Bool("managed", cert.managed),
		zap.String("issuer_key", cert.issuerKey),
		zap.String("hash", cert.hash),
		zap.Int("cache_size", len(certCache.cache)),
		zap.Int("cache_capacity", certCache.options.Capacity),
		zap.Int("max_memory_mb", certCache.options.MaxMemoryMB),
		zap.Int64("memory_bytes", certCache.currentMemoryBytes))
	certCache.optionsMu.RUnlock()
}

// replaceCertificate atomically replaces oldCert with newCert in
// the cache.
//
// This method is safe for concurrent use.
func (certCache *Cache) replaceCertificate(oldCert, newCert Certificate) {
	certCache.mu.Lock()
	certCache.removeCertificate(oldCert.hash)
	certCache.unsyncedCacheCertificate(newCert)
	certCache.mu.Unlock()
	certCache.logger.Info("replaced certificate in cache",
		zap.Strings("subjects", newCert.Names),
		zap.Time("new_expiration", expiresAt(newCert.Leaf)))
}

// getAllMatchingCerts returns all certificates with exactly this subject
// (wildcards are NOT expanded).
func (certCache *Cache) getAllMatchingCerts(subject string) []Certificate {
	certCache.mu.Lock()
	defer certCache.mu.Unlock()

	allCertKeys := certCache.cacheIndex[subject]

	certs := make([]Certificate, len(allCertKeys))
	for i := range allCertKeys {
		certHash := allCertKeys[i]
		certs[i] = certCache.cache[certHash]
		// Update LRU since certificate was accessed
		certCache.updateLRU(certHash)
	}

	return certs
}

func (certCache *Cache) getAllCerts() []Certificate {
	certCache.mu.RLock()
	defer certCache.mu.RUnlock()
	certs := make([]Certificate, 0, len(certCache.cache))
	for _, cert := range certCache.cache {
		certs = append(certs, cert)
	}
	return certs
}

func (certCache *Cache) getConfig(cert Certificate) (*Config, error) {
	certCache.optionsMu.RLock()
	getCert := certCache.options.GetConfigForCert
	certCache.optionsMu.RUnlock()

	cfg, err := getCert(cert)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		// this is bad if this happens, probably a programmer error (oops)
		return nil, fmt.Errorf("no configuration associated with certificate: %v;", cert.Names)
	}
	if cfg.certCache == nil {
		return nil, fmt.Errorf("config returned for certificate %v has nil cache; expected %p (this one)",
			cert.Names, certCache)
	}
	if cfg.certCache != certCache {
		return nil, fmt.Errorf("config returned for certificate %v is not nil and points to different cache; got %p, expected %p (this one)",
			cert.Names, cfg.certCache, certCache)
	}
	return cfg, nil
}

// AllMatchingCertificates returns a list of all certificates that could
// be used to serve the given SNI name, including exact SAN matches and
// wildcard matches.
func (certCache *Cache) AllMatchingCertificates(name string) []Certificate {
	// get exact matches first
	certs := certCache.getAllMatchingCerts(name)

	// then look for wildcard matches by replacing each
	// label of the domain name with wildcards
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		certs = append(certs, certCache.getAllMatchingCerts(candidate)...)
	}

	return certs
}

// SubjectIssuer pairs a subject name with an issuer ID/key.
type SubjectIssuer struct {
	Subject, IssuerKey string
}

// RemoveManaged removes managed certificates for the given subjects from the cache.
// This effectively stops maintenance of those certificates. If an IssuerKey is
// specified alongside the subject, only certificates for that subject from the
// specified issuer will be removed.
func (certCache *Cache) RemoveManaged(subjects []SubjectIssuer) {
	deleteQueue := make([]string, 0, len(subjects))
	for _, subj := range subjects {
		certs := certCache.getAllMatchingCerts(subj.Subject) // does NOT expand wildcards; exact matches only
		for _, cert := range certs {
			if !cert.managed {
				continue
			}
			if subj.IssuerKey == "" || cert.issuerKey == subj.IssuerKey {
				deleteQueue = append(deleteQueue, cert.hash)
			}
		}
	}
	certCache.Remove(deleteQueue)
}

// Remove removes certificates with the given hashes from the cache.
// This is effectively used to unload manually-loaded certificates.
func (certCache *Cache) Remove(hashes []string) {
	certCache.mu.Lock()
	for _, h := range hashes {
		certCache.removeCertificate(h)
	}
	certCache.mu.Unlock()
}

var (
	defaultCache   *Cache
	defaultCacheMu sync.Mutex
)
