// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"database/sql"
	"fmt"
	"time"
)

// InitCustomTables creates the rendezvous-specific tables (tokens, enrolled keys, audit).
// The core FDO tables (rv_blobs, sessions, etc.) are created by sqlite.Open/Init.
func InitCustomTables(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS rv_auth_tokens
			( token TEXT PRIMARY KEY
			, description TEXT NOT NULL DEFAULT ''
			, expires_at INTEGER  -- Unix timestamp; NULL = never expires
			, created_at INTEGER NOT NULL
			)`,

		`CREATE TABLE IF NOT EXISTS rv_enrolled_keys
			( id INTEGER PRIMARY KEY AUTOINCREMENT
			, key_type TEXT NOT NULL  -- 'pem' or 'did'
			, key_data TEXT NOT NULL  -- PEM-encoded public key
			, fingerprint TEXT NOT NULL  -- hex-encoded SHA-256 of PKIX DER
			, did_uri TEXT  -- DID URI if enrolled via DID:web
			, description TEXT NOT NULL DEFAULT ''
			, last_resolved_at INTEGER  -- Unix timestamp of last DID:web resolution
			, created_at INTEGER NOT NULL
			)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS rv_enrolled_keys_fingerprint
			ON rv_enrolled_keys(fingerprint)`,

		`CREATE TABLE IF NOT EXISTS rv_blob_audit
			( guid BLOB NOT NULL
			, uploader_type TEXT NOT NULL  -- 'open', 'token', 'signatory'
			, uploader_id TEXT NOT NULL DEFAULT ''  -- token value or key fingerprint
			, uploaded_at INTEGER NOT NULL
			)`,
		`CREATE INDEX IF NOT EXISTS rv_blob_audit_guid
			ON rv_blob_audit(guid)`,
	}

	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("creating custom table: %w", err)
		}
	}
	return nil
}

// Token represents an authentication token for TO0 access.
type Token struct {
	Token       string
	Description string
	ExpiresAt   *time.Time // nil = never expires
	CreatedAt   time.Time
}

// AddToken inserts a new auth token.
func AddToken(db *sql.DB, token, description string, expiresAt *time.Time) error {
	var exp *int64
	if expiresAt != nil {
		t := expiresAt.Unix()
		exp = &t
	}
	_, err := db.Exec(
		`INSERT INTO rv_auth_tokens (token, description, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		token, description, exp, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("adding token: %w", err)
	}
	return nil
}

// ValidateToken checks if a token exists and is not expired.
func ValidateToken(db *sql.DB, token string) (bool, error) {
	var exp sql.NullInt64
	err := db.QueryRow(
		`SELECT expires_at FROM rv_auth_tokens WHERE token = ?`, token,
	).Scan(&exp)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("validating token: %w", err)
	}
	if exp.Valid && time.Unix(exp.Int64, 0).Before(time.Now()) {
		return false, nil // expired
	}
	return true, nil
}

// ListTokens returns all tokens.
func ListTokens(db *sql.DB) ([]Token, error) {
	rows, err := db.Query(`SELECT token, description, expires_at, created_at FROM rv_auth_tokens ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing tokens: %w", err)
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		var t Token
		var exp sql.NullInt64
		var created int64
		if err := rows.Scan(&t.Token, &t.Description, &exp, &created); err != nil {
			return nil, fmt.Errorf("scanning token: %w", err)
		}
		t.CreatedAt = time.Unix(created, 0)
		if exp.Valid {
			e := time.Unix(exp.Int64, 0)
			t.ExpiresAt = &e
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// DeleteToken removes a token.
func DeleteToken(db *sql.DB, token string) error {
	res, err := db.Exec(`DELETE FROM rv_auth_tokens WHERE token = ?`, token)
	if err != nil {
		return fmt.Errorf("deleting token: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

// CleanupExpiredTokens removes all expired tokens.
func CleanupExpiredTokens(db *sql.DB) (int64, error) {
	res, err := db.Exec(`DELETE FROM rv_auth_tokens WHERE expires_at IS NOT NULL AND expires_at < ?`, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("cleaning up expired tokens: %w", err)
	}
	return res.RowsAffected()
}

// EnrolledKey represents an enrolled public key for signatory auth.
type EnrolledKey struct {
	ID             int64
	KeyType        string // "pem" or "did"
	KeyData        string // PEM-encoded public key
	Fingerprint    string // hex SHA-256
	DIDURI         string
	Description    string
	LastResolvedAt *time.Time
	CreatedAt      time.Time
}

// AddEnrolledKey inserts a new enrolled key.
func AddEnrolledKey(db *sql.DB, keyType, keyData, fingerprint, didURI, description string) (int64, error) {
	var lastResolved *int64
	if didURI != "" {
		t := time.Now().Unix()
		lastResolved = &t
	}
	res, err := db.Exec(
		`INSERT INTO rv_enrolled_keys (key_type, key_data, fingerprint, did_uri, description, last_resolved_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		keyType, keyData, fingerprint, sql.NullString{String: didURI, Valid: didURI != ""},
		description, lastResolved, time.Now().Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("adding enrolled key: %w", err)
	}
	return res.LastInsertId()
}

// FindEnrolledKeyByFingerprint looks up an enrolled key by its fingerprint.
func FindEnrolledKeyByFingerprint(db *sql.DB, fingerprint string) (*EnrolledKey, error) {
	var k EnrolledKey
	var didURI sql.NullString
	var lastResolved sql.NullInt64
	var created int64

	err := db.QueryRow(
		`SELECT id, key_type, key_data, fingerprint, did_uri, description, last_resolved_at, created_at
		 FROM rv_enrolled_keys WHERE fingerprint = ?`, fingerprint,
	).Scan(&k.ID, &k.KeyType, &k.KeyData, &k.Fingerprint, &didURI, &k.Description, &lastResolved, &created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("finding enrolled key: %w", err)
	}
	k.CreatedAt = time.Unix(created, 0)
	if didURI.Valid {
		k.DIDURI = didURI.String
	}
	if lastResolved.Valid {
		t := time.Unix(lastResolved.Int64, 0)
		k.LastResolvedAt = &t
	}
	return &k, nil
}

// ListEnrolledKeys returns all enrolled keys.
func ListEnrolledKeys(db *sql.DB) ([]EnrolledKey, error) {
	rows, err := db.Query(
		`SELECT id, key_type, key_data, fingerprint, did_uri, description, last_resolved_at, created_at
		 FROM rv_enrolled_keys ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("listing enrolled keys: %w", err)
	}
	defer rows.Close()

	var keys []EnrolledKey
	for rows.Next() {
		var k EnrolledKey
		var didURI sql.NullString
		var lastResolved sql.NullInt64
		var created int64
		if err := rows.Scan(&k.ID, &k.KeyType, &k.KeyData, &k.Fingerprint, &didURI, &k.Description, &lastResolved, &created); err != nil {
			return nil, fmt.Errorf("scanning enrolled key: %w", err)
		}
		k.CreatedAt = time.Unix(created, 0)
		if didURI.Valid {
			k.DIDURI = didURI.String
		}
		if lastResolved.Valid {
			t := time.Unix(lastResolved.Int64, 0)
			k.LastResolvedAt = &t
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// DeleteEnrolledKey removes an enrolled key by ID or fingerprint.
func DeleteEnrolledKey(db *sql.DB, idOrFingerprint string) error {
	res, err := db.Exec(
		`DELETE FROM rv_enrolled_keys WHERE CAST(id AS TEXT) = ? OR fingerprint = ?`,
		idOrFingerprint, idOrFingerprint,
	)
	if err != nil {
		return fmt.Errorf("deleting enrolled key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("enrolled key not found")
	}
	return nil
}

// UpdateEnrolledKeyFingerprint updates the fingerprint and key data for a DID-enrolled key after re-resolution.
func UpdateEnrolledKeyFingerprint(db *sql.DB, id int64, newKeyData, newFingerprint string) error {
	_, err := db.Exec(
		`UPDATE rv_enrolled_keys SET key_data = ?, fingerprint = ?, last_resolved_at = ? WHERE id = ?`,
		newKeyData, newFingerprint, time.Now().Unix(), id,
	)
	return err
}

// LogBlobUpload records a blob upload in the audit table.
func LogBlobUpload(db *sql.DB, guid []byte, uploaderType, uploaderID string) error {
	_, err := db.Exec(
		`INSERT INTO rv_blob_audit (guid, uploader_type, uploader_id, uploaded_at) VALUES (?, ?, ?, ?)`,
		guid, uploaderType, uploaderID, time.Now().Unix(),
	)
	return err
}

// BlobAuditEntry represents a row in the blob audit log.
type BlobAuditEntry struct {
	GUID         []byte
	UploaderType string
	UploaderID   string
	UploadedAt   time.Time
}

// ListBlobAudit returns blob audit entries, optionally filtered by uploader.
func ListBlobAudit(db *sql.DB, uploaderFilter string) ([]BlobAuditEntry, error) {
	var rows *sql.Rows
	var err error
	if uploaderFilter != "" {
		rows, err = db.Query(
			`SELECT guid, uploader_type, uploader_id, uploaded_at FROM rv_blob_audit
			 WHERE uploader_id = ? ORDER BY uploaded_at DESC`, uploaderFilter,
		)
	} else {
		rows, err = db.Query(
			`SELECT guid, uploader_type, uploader_id, uploaded_at FROM rv_blob_audit ORDER BY uploaded_at DESC`,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing blob audit: %w", err)
	}
	defer rows.Close()

	var entries []BlobAuditEntry
	for rows.Next() {
		var e BlobAuditEntry
		var uploaded int64
		if err := rows.Scan(&e.GUID, &e.UploaderType, &e.UploaderID, &uploaded); err != nil {
			return nil, fmt.Errorf("scanning blob audit: %w", err)
		}
		e.UploadedAt = time.Unix(uploaded, 0)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// PurgeExpiredBlobs deletes RV blobs that have expired.
func PurgeExpiredBlobs(db *sql.DB) (int64, error) {
	res, err := db.Exec(`DELETE FROM rv_blobs WHERE exp < ?`, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("purging expired blobs: %w", err)
	}
	return res.RowsAffected()
}
