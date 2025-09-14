package certmagic

import (
    "crypto/tls"
    "reflect"
    "testing"
)

// ptr returns the address of the first byte of b for pointer identity checks.
func ptr(b []byte) uintptr {
    if len(b) == 0 {
        return 0
    }
    return reflect.ValueOf(&b[0]).Pointer()
}

func TestDERInterningOnCacheInsert(t *testing.T) {
    noop := func(Certificate) (*Config, error) { return new(Config), nil }
    c := NewCache(CacheOptions{GetConfigForCert: noop})
    defer c.Stop()

    // Construct two certificates that share the same intermediate DER bytes
    inter := []byte("INTERMEDIATE-DER")
    leaf1 := []byte("LEAF1")
    leaf2 := []byte("LEAF2")

    cert1 := Certificate{
        Certificate: tls.Certificate{Certificate: [][]byte{leaf1, inter}},
        Names:       []string{"a.example.com"},
        hash:        "h1",
    }
    cert2 := Certificate{
        Certificate: tls.Certificate{Certificate: [][]byte{leaf2, append([]byte(nil), inter...)}},
        Names:       []string{"b.example.com"},
        hash:        "h2",
    }

    // Insert both into cache
    c.cacheCertificate(cert1)
    c.cacheCertificate(cert2)

    got1 := c.cache["h1"].Certificate.Certificate[1]
    got2 := c.cache["h2"].Certificate.Certificate[1]

    if !reflect.DeepEqual(got1, inter) || !reflect.DeepEqual(got2, inter) {
        t.Fatalf("unexpected intermediate bytes after caching")
    }
    if ptr(got1) != ptr(got2) {
        t.Fatalf("expected interned intermediate to share backing storage; ptr1=%v ptr2=%v", ptr(got1), ptr(got2))
    }
}

