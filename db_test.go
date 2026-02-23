// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	// Use a temp file DB to avoid :memory: connection pooling issues.
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
	if err := InitCustomTables(db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestInitCustomTables(t *testing.T) {
	db := openTestDB(t)

	// Verify tables exist by querying them
	for _, table := range []string{"rv_auth_tokens", "rv_enrolled_keys", "rv_blob_audit"} {
		_, err := db.Query("SELECT * FROM " + table + " LIMIT 1")
		if err != nil {
			t.Errorf("table %s not created: %v", table, err)
		}
	}
}

func TestInitCustomTables_Idempotent(t *testing.T) {
	db := openTestDB(t)
	// Second call should not fail
	if err := InitCustomTables(db); err != nil {
		t.Errorf("second InitCustomTables failed: %v", err)
	}
}

func TestTokenCRUD(t *testing.T) {
	db := openTestDB(t)

	// Add token
	if err := AddToken(db, "test-token-1", "test token", nil); err != nil {
		t.Fatal(err)
	}

	// Add token with expiry
	exp := time.Now().Add(1 * time.Hour)
	if err := AddToken(db, "test-token-2", "expiring token", &exp); err != nil {
		t.Fatal(err)
	}

	// List tokens
	tokens, err := ListTokens(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}

	// Validate valid token
	valid, err := ValidateToken(db, "test-token-1")
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("expected token to be valid")
	}

	// Validate non-existent token
	valid, err = ValidateToken(db, "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("expected nonexistent token to be invalid")
	}

	// Delete token
	if err := DeleteToken(db, "test-token-1"); err != nil {
		t.Fatal(err)
	}
	valid, err = ValidateToken(db, "test-token-1")
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("expected deleted token to be invalid")
	}

	// Delete non-existent token
	if err := DeleteToken(db, "nonexistent"); err == nil {
		t.Error("expected error deleting nonexistent token")
	}
}

func TestTokenExpiry(t *testing.T) {
	db := openTestDB(t)

	// Add expired token
	exp := time.Now().Add(-1 * time.Hour)
	if err := AddToken(db, "expired-token", "expired", &exp); err != nil {
		t.Fatal(err)
	}

	valid, err := ValidateToken(db, "expired-token")
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("expected expired token to be invalid")
	}

	// Cleanup expired
	n, err := CleanupExpiredTokens(db)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 expired token cleaned, got %d", n)
	}
}

func TestEnrolledKeyCRUD(t *testing.T) {
	db := openTestDB(t)

	// Add key
	id, err := AddEnrolledKey(db, "pem", "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----", "abcdef1234567890", "", "test key")
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Error("expected non-zero ID")
	}

	// Find by fingerprint
	key, err := FindEnrolledKeyByFingerprint(db, "abcdef1234567890")
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("expected to find key")
	}
	if key.KeyType != "pem" {
		t.Errorf("expected pem, got %s", key.KeyType)
	}
	if key.Description != "test key" {
		t.Errorf("expected 'test key', got %s", key.Description)
	}

	// Find nonexistent
	key, err = FindEnrolledKeyByFingerprint(db, "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if key != nil {
		t.Error("expected nil for nonexistent fingerprint")
	}

	// Add DID key
	id2, err := AddEnrolledKey(db, "did", "-----BEGIN PUBLIC KEY-----\ntest2\n-----END PUBLIC KEY-----", "fedcba0987654321", "did:web:example.com", "did key")
	if err != nil {
		t.Fatal(err)
	}

	// List keys
	keys, err := ListEnrolledKeys(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	// DID key should have last_resolved_at set
	for _, k := range keys {
		if k.DIDURI == "did:web:example.com" && k.LastResolvedAt == nil {
			t.Error("expected DID key to have last_resolved_at")
		}
	}

	// Update fingerprint
	if err := UpdateEnrolledKeyFingerprint(db, id2, "new-pem-data", "newfp1234567890"); err != nil {
		t.Fatal(err)
	}
	updated, _ := FindEnrolledKeyByFingerprint(db, "newfp1234567890")
	if updated == nil {
		t.Fatal("expected to find updated key")
	}

	// Delete by fingerprint
	if err := DeleteEnrolledKey(db, "newfp1234567890"); err != nil {
		t.Fatal(err)
	}

	keys, _ = ListEnrolledKeys(db)
	if len(keys) != 1 {
		t.Errorf("expected 1 key after delete, got %d", len(keys))
	}
}

func TestBlobAudit(t *testing.T) {
	db := openTestDB(t)

	guid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	if err := LogBlobUpload(db, guid, "open", ""); err != nil {
		t.Fatal(err)
	}
	if err := LogBlobUpload(db, guid, "token", "my-token"); err != nil {
		t.Fatal(err)
	}

	// List all
	entries, err := ListBlobAudit(db, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Filter by uploader
	entries, err = ListBlobAudit(db, "my-token")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry for my-token, got %d", len(entries))
	}
}
