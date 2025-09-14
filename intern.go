package certmagic

import (
    "crypto/sha256"
    "sync"
)

// derIntern provides interning for DER-encoded byte slices so that
// identical chains across many certificates share a single backing slice.
// Keys are SHA-256 hashes of the DER bytes.
type derIntern struct {
    mu sync.RWMutex
    m  map[[32]byte][]byte
}

func (di *derIntern) init() {
    di.mu.Lock()
    if di.m == nil {
        di.m = make(map[[32]byte][]byte)
    }
    di.mu.Unlock()
}

// intern returns a canonical backing slice for b. If an identical slice
// has already been interned, that slice is returned. Otherwise a tight
// copy is made, stored, and returned.
func (di *derIntern) intern(b []byte) []byte {
    if len(b) == 0 {
        return b
    }
    sum := sha256.Sum256(b)
    di.mu.RLock()
    if v, ok := di.m[sum]; ok {
        di.mu.RUnlock()
        return v
    }
    di.mu.RUnlock()

    // Make a tight copy to avoid carrying excess capacity.
    tight := append([]byte(nil), b...)

    di.mu.Lock()
    if v, ok := di.m[sum]; ok {
        di.mu.Unlock()
        return v
    }
    di.m[sum] = tight
    di.mu.Unlock()
    return tight
}

