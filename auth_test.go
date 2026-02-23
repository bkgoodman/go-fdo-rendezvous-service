// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsTO0Message(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/fdo/101/msg/20", true},
		{"/fdo/101/msg/22", true},
		{"/fdo/200/msg/20", true},
		{"/fdo/101/msg/30", false}, // TO1
		{"/fdo/101/msg/32", false}, // TO1
		{"/fdo/101/msg/60", false}, // TO2
		{"/fdo/101/msg/10", false}, // DI
		{"/invalid", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isTO0Message(tt.path)
		if got != tt.want {
			t.Errorf("isTO0Message(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestTokenAuthMiddleware_TO0Blocked(t *testing.T) {
	db := openTestDB(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := TokenAuthMiddleware(db, inner)

	// TO0 without token => 401
	req := httptest.NewRequest("POST", "/fdo/101/msg/20", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for TO0 without token, got %d", w.Code)
	}
}

func TestTokenAuthMiddleware_TO0WithValidToken(t *testing.T) {
	db := openTestDB(t)
	AddToken(db, "valid-token", "test", nil)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ut, uid := uploaderFromContext(r.Context())
		if ut != "token" {
			t.Errorf("expected uploader type 'token', got %q", ut)
		}
		if uid != "valid-token" {
			t.Errorf("expected uploader id 'valid-token', got %q", uid)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := TokenAuthMiddleware(db, inner)

	req := httptest.NewRequest("POST", "/fdo/101/msg/20", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestTokenAuthMiddleware_TO1PassThrough(t *testing.T) {
	db := openTestDB(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := TokenAuthMiddleware(db, inner)

	// TO1 without token => should pass through
	req := httptest.NewRequest("POST", "/fdo/101/msg/30", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for TO1 without token, got %d", w.Code)
	}
}

func TestPublicKeyFingerprint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	fp1, err := PublicKeyFingerprint(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if len(fp1) != 64 { // hex-encoded SHA-256 = 64 chars
		t.Errorf("expected 64 char fingerprint, got %d", len(fp1))
	}

	// Deterministic
	fp2, _ := PublicKeyFingerprint(key.Public())
	if fp1 != fp2 {
		t.Error("fingerprints should be deterministic")
	}

	// Different key = different fingerprint
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fp3, _ := PublicKeyFingerprint(key2.Public())
	if fp1 == fp3 {
		t.Error("different keys should have different fingerprints")
	}
}

func TestParsePEMPublicKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(key.Public())
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	pub, fp, err := ParsePEMPublicKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
	if len(fp) != 64 {
		t.Errorf("expected 64 char fingerprint, got %d", len(fp))
	}
}

func TestParsePEMPublicKey_Invalid(t *testing.T) {
	_, _, err := ParsePEMPublicKey([]byte("not a pem"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}
