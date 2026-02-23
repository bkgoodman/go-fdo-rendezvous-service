// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	fdodid "github.com/fido-device-onboard/go-fdo/did"
)

// DIDResolver handles DID:web resolution with lazy best-effort refresh.
type DIDResolver struct {
	db               *sql.DB
	refreshThreshold time.Duration
	resolver         *fdodid.Resolver
	mu               sync.Mutex // guards concurrent refresh goroutines
}

// NewDIDResolver creates a DID resolver with the given refresh threshold.
func NewDIDResolver(db *sql.DB, refreshThreshold time.Duration, insecureHTTP bool) *DIDResolver {
	r := fdodid.NewResolver()
	if insecureHTTP {
		r.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &DIDResolver{
		db:               db,
		refreshThreshold: refreshThreshold,
		resolver:         r,
	}
}

// EnrollDID resolves a DID:web URI, extracts the public key, and enrolls it.
// Returns the enrolled key fingerprint.
func (d *DIDResolver) EnrollDID(ctx context.Context, didURI, description string) (string, error) {
	result, err := d.resolver.Resolve(ctx, didURI)
	if err != nil {
		return "", fmt.Errorf("resolving DID %q: %w", didURI, err)
	}

	keyPEM, err := publicKeyToPEM(result.PublicKey)
	if err != nil {
		return "", fmt.Errorf("encoding resolved key: %w", err)
	}

	fp, err := PublicKeyFingerprint(result.PublicKey)
	if err != nil {
		return "", err
	}

	_, err = AddEnrolledKey(d.db, "did", string(keyPEM), fp, didURI, description)
	if err != nil {
		return "", fmt.Errorf("enrolling DID key: %w", err)
	}

	slog.Info("DID key enrolled", "did", didURI, "fingerprint", fp)
	return fp, nil
}

// MaybeLazyRefresh checks if an enrolled DID key is stale and triggers a
// background re-resolution if so. Returns immediately — the current cached
// fingerprint is used for the current request.
func (d *DIDResolver) MaybeLazyRefresh(key *EnrolledKey) {
	if key.DIDURI == "" || key.LastResolvedAt == nil {
		return
	}
	if time.Since(*key.LastResolvedAt) < d.refreshThreshold {
		return
	}

	// Trigger background refresh (best-effort, don't block)
	go func() {
		d.mu.Lock()
		defer d.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := d.resolver.Resolve(ctx, key.DIDURI)
		if err != nil {
			slog.Warn("DID lazy refresh failed", "did", key.DIDURI, "error", err)
			return
		}

		newFP, err := PublicKeyFingerprint(result.PublicKey)
		if err != nil {
			slog.Warn("DID lazy refresh: fingerprint error", "did", key.DIDURI, "error", err)
			return
		}

		if newFP != key.Fingerprint {
			newPEM, err := publicKeyToPEM(result.PublicKey)
			if err != nil {
				slog.Warn("DID lazy refresh: PEM encode error", "did", key.DIDURI, "error", err)
				return
			}
			if err := UpdateEnrolledKeyFingerprint(d.db, key.ID, string(newPEM), newFP); err != nil {
				slog.Warn("DID lazy refresh: DB update error", "did", key.DIDURI, "error", err)
				return
			}
			slog.Info("DID key refreshed with new fingerprint", "did", key.DIDURI, "old_fp", key.Fingerprint, "new_fp", newFP)
		} else {
			// Just update last_resolved_at timestamp
			_, _ = d.db.Exec(`UPDATE rv_enrolled_keys SET last_resolved_at = ? WHERE id = ?`, time.Now().Unix(), key.ID)
			slog.Debug("DID key refresh: fingerprint unchanged", "did", key.DIDURI)
		}
	}()
}

// publicKeyToPEM encodes a crypto.PublicKey as PEM.
func publicKeyToPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key to PKIX: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
