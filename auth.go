// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/fido-device-onboard/go-fdo"
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const (
	// ctxKeyUploaderType stores the uploader type (open/token/signatory) in context.
	ctxKeyUploaderType contextKey = iota
	// ctxKeyUploaderID stores the uploader identity (token or fingerprint) in context.
	ctxKeyUploaderID
)

// uploaderFromContext extracts uploader info from context.
func uploaderFromContext(ctx context.Context) (uploaderType, uploaderID string) {
	if v, ok := ctx.Value(ctxKeyUploaderType).(string); ok {
		uploaderType = v
	}
	if v, ok := ctx.Value(ctxKeyUploaderID).(string); ok {
		uploaderID = v
	}
	return
}

// TokenAuthMiddleware wraps an http.Handler to require Bearer token auth on TO0 messages.
// TO1 messages pass through unauthenticated (device auth is protocol-native).
func TokenAuthMiddleware(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only gate TO0 message types (msg 20 = Hello, msg 22 = OwnerSign)
		// TO1 messages (30, 32) pass through.
		// Path format: /fdo/{ver}/msg/{type}
		if isTO0Message(r.URL.Path) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, "Authorization: Bearer token required for TO0", http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")
			valid, err := ValidateToken(db, token)
			if err != nil {
				slog.Error("token validation error", "error", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if !valid {
				http.Error(w, "invalid or expired token", http.StatusUnauthorized)
				return
			}
			// Thread token identity into context for audit
			ctx := context.WithValue(r.Context(), ctxKeyUploaderType, "token")
			ctx = context.WithValue(ctx, ctxKeyUploaderID, token)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// isTO0Message checks if the URL path corresponds to a TO0 message type (20 or 22).
func isTO0Message(path string) bool {
	// Path format: /fdo/{ver}/msg/{type}
	parts := strings.Split(strings.TrimPrefix(path, "/fdo/"), "/")
	if len(parts) != 3 || parts[1] != "msg" {
		return false
	}
	return parts[2] == "20" || parts[2] == "22"
}

// MakeAcceptVoucher creates an AcceptVoucher callback for the given auth mode and config.
func MakeAcceptVoucher(cfg *Config, db *sql.DB) func(context.Context, fdo.Voucher, uint32) (uint32, error) {
	return func(ctx context.Context, ov fdo.Voucher, requestedTTL uint32) (uint32, error) {
		ttl := requestedTTL
		if ttl > cfg.RV.MaxTTL {
			ttl = cfg.RV.MaxTTL
		}

		uploaderType, uploaderID := uploaderFromContext(ctx)

		guid := ov.Header.Val.GUID

		switch cfg.Auth.Mode {
		case "open":
			if uploaderType == "" {
				uploaderType = "open"
			}
			slog.Info("TO0 accepted (open mode)", "guid", guid, "ttl", ttl)

		case "token":
			// Token already validated by middleware; just log
			if uploaderType != "token" {
				return 0, fmt.Errorf("token auth required but no token in context")
			}
			slog.Info("TO0 accepted (token mode)", "guid", guid, "ttl", ttl)

		case "signatory":
			// Check that the voucher's owner key is enrolled
			fp, err := voucherOwnerFingerprint(ov)
			if err != nil {
				return 0, fmt.Errorf("extracting owner key fingerprint: %w", err)
			}

			enrolled, err := FindEnrolledKeyByFingerprint(db, fp)
			if err != nil {
				return 0, fmt.Errorf("checking enrolled key: %w", err)
			}
			if enrolled == nil {
				slog.Warn("TO0 rejected: owner key not enrolled", "fingerprint", fp, "guid", guid)
				return 0, fmt.Errorf("owner key fingerprint %s is not enrolled", fp)
			}

			uploaderType = "signatory"
			uploaderID = fp
			slog.Info("TO0 accepted (signatory mode)", "guid", guid, "fingerprint", fp, "ttl", ttl)
		}

		// Audit log
		if err := LogBlobUpload(db, guid[:], uploaderType, uploaderID); err != nil {
			slog.Error("failed to log blob upload", "error", err)
			// Non-fatal: don't reject the upload for audit failure
		}

		return ttl, nil
	}
}

// voucherOwnerFingerprint extracts the owner public key from a voucher and returns its hex SHA-256 fingerprint.
func voucherOwnerFingerprint(ov fdo.Voucher) (string, error) {
	entries := ov.Entries
	var ownerPubKey crypto.PublicKey

	if len(entries) > 0 {
		// Last entry's public key is the current owner
		lastEntry := entries[len(entries)-1]
		var err error
		ownerPubKey, err = lastEntry.Payload.Val.PublicKey.Public()
		if err != nil {
			return "", fmt.Errorf("extracting owner public key from entry: %w", err)
		}
	} else {
		// No entries = manufacturer key is the owner
		var err error
		ownerPubKey, err = ov.Header.Val.ManufacturerKey.Public()
		if err != nil {
			return "", fmt.Errorf("extracting manufacturer public key: %w", err)
		}
	}

	return PublicKeyFingerprint(ownerPubKey)
}

// PublicKeyFingerprint computes the hex-encoded SHA-256 fingerprint of a public key's PKIX DER encoding.
func PublicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshaling public key: %w", err)
	}
	hash := sha256.Sum256(der)
	return hex.EncodeToString(hash[:]), nil
}

// ParsePEMPublicKey parses a PEM-encoded public key and returns the key and its fingerprint.
func ParsePEMPublicKey(pemData []byte) (crypto.PublicKey, string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, "", fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parsing public key: %w", err)
	}
	fp, err := PublicKeyFingerprint(pub)
	if err != nil {
		return nil, "", err
	}
	return pub, fp, nil
}
