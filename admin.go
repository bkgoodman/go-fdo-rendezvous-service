// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// handleTokenManagement handles CLI token admin commands. Returns true if a command was handled.
func handleTokenManagement(db *sql.DB) (bool, error) {
	if *listTokens {
		return true, cmdListTokens(db)
	}
	if *addToken != "" {
		return true, cmdAddToken(db, *addToken)
	}
	if *deleteToken != "" {
		return true, cmdDeleteToken(db, *deleteToken)
	}
	if *cleanupTokens {
		return true, cmdCleanupExpiredTokens(db)
	}
	return false, nil
}

// handleKeyManagement handles CLI key enrollment commands. Returns true if a command was handled.
func handleKeyManagement(db *sql.DB, didResolver *DIDResolver) (bool, error) {
	if *enrollKey != "" {
		return true, cmdEnrollKey(db, *enrollKey)
	}
	if *enrollDID != "" {
		return true, cmdEnrollDID(db, didResolver, *enrollDID)
	}
	if *listKeys {
		return true, cmdListKeys(db)
	}
	if *deleteKey != "" {
		return true, cmdDeleteKey(db, *deleteKey)
	}
	return false, nil
}

// handleBlobManagement handles CLI blob admin commands. Returns true if a command was handled.
func handleBlobManagement(db *sql.DB) (bool, error) {
	if *listBlobs {
		return true, cmdListBlobs(db, "")
	}
	if *listBlobsByUploader != "" {
		return true, cmdListBlobs(db, *listBlobsByUploader)
	}
	if *purgeExpired {
		return true, cmdPurgeExpired(db)
	}
	if *purgeInactive > 0 {
		return true, cmdPurgeInactive(db, *purgeInactive)
	}
	if *purgeByUploader != "" {
		return true, cmdPurgeByUploader(db, *purgeByUploader)
	}
	return false, nil
}

func cmdListTokens(db *sql.DB) error {
	tokens, err := ListTokens(db)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		fmt.Println("No tokens configured.")
		return nil
	}
	fmt.Printf("%-40s %-30s %-20s %s\n", "TOKEN", "DESCRIPTION", "EXPIRES", "CREATED")
	for _, t := range tokens {
		exp := "never"
		if t.ExpiresAt != nil {
			exp = t.ExpiresAt.Format(time.RFC3339)
		}
		fmt.Printf("%-40s %-30s %-20s %s\n", t.Token, t.Description, exp, t.CreatedAt.Format(time.RFC3339))
	}
	return nil
}

func cmdAddToken(db *sql.DB, spec string) error {
	// Format: "<token> <description> <expires_hours>"
	parts := strings.SplitN(spec, " ", 3)
	if len(parts) < 1 {
		return fmt.Errorf("usage: -add-token '<token> [description] [expires_hours]'")
	}
	token := parts[0]
	description := ""
	var expiresAt *time.Time

	if len(parts) >= 2 {
		description = parts[1]
	}
	if len(parts) >= 3 {
		hours, err := strconv.Atoi(parts[2])
		if err != nil {
			return fmt.Errorf("invalid expires_hours %q: %w", parts[2], err)
		}
		t := time.Now().Add(time.Duration(hours) * time.Hour)
		expiresAt = &t
	}

	if err := AddToken(db, token, description, expiresAt); err != nil {
		return err
	}
	fmt.Printf("Token added: %s\n", token)
	return nil
}

func cmdDeleteToken(db *sql.DB, token string) error {
	if err := DeleteToken(db, token); err != nil {
		return err
	}
	fmt.Printf("Token deleted: %s\n", token)
	return nil
}

func cmdCleanupExpiredTokens(db *sql.DB) error {
	n, err := CleanupExpiredTokens(db)
	if err != nil {
		return err
	}
	fmt.Printf("Removed %d expired token(s).\n", n)
	return nil
}

func cmdEnrollKey(db *sql.DB, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading key file %q: %w", path, err)
	}
	_, fp, err := ParsePEMPublicKey(data)
	if err != nil {
		return fmt.Errorf("parsing key file %q: %w", path, err)
	}

	id, err := AddEnrolledKey(db, "pem", string(data), fp, "", path)
	if err != nil {
		return err
	}
	fmt.Printf("Key enrolled: id=%d fingerprint=%s\n", id, fp)
	return nil
}

func cmdEnrollDID(db *sql.DB, resolver *DIDResolver, didURI string) error {
	fp, err := resolver.EnrollDID(context.Background(), didURI, didURI)
	if err != nil {
		return err
	}
	fmt.Printf("DID key enrolled: %s fingerprint=%s\n", didURI, fp)
	return nil
}

func cmdListKeys(db *sql.DB) error {
	keys, err := ListEnrolledKeys(db)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Println("No enrolled keys.")
		return nil
	}
	fmt.Printf("%-5s %-5s %-64s %-40s %-20s %s\n", "ID", "TYPE", "FINGERPRINT", "DID URI", "LAST RESOLVED", "DESCRIPTION")
	for _, k := range keys {
		resolved := "n/a"
		if k.LastResolvedAt != nil {
			resolved = k.LastResolvedAt.Format(time.RFC3339)
		}
		didURI := k.DIDURI
		if didURI == "" {
			didURI = "-"
		}
		fmt.Printf("%-5d %-5s %-64s %-40s %-20s %s\n", k.ID, k.KeyType, k.Fingerprint, didURI, resolved, k.Description)
	}
	return nil
}

func cmdDeleteKey(db *sql.DB, idOrFP string) error {
	if err := DeleteEnrolledKey(db, idOrFP); err != nil {
		return err
	}
	fmt.Printf("Enrolled key deleted: %s\n", idOrFP)
	return nil
}

func cmdListBlobs(db *sql.DB, uploaderFilter string) error {
	entries, err := ListBlobAudit(db, uploaderFilter)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("No blob audit entries.")
		return nil
	}
	fmt.Printf("%-36s %-12s %-40s %s\n", "GUID", "UPLOADER", "UPLOADER ID", "UPLOADED AT")
	for _, e := range entries {
		fmt.Printf("%-36s %-12s %-40s %s\n",
			hex.EncodeToString(e.GUID),
			e.UploaderType,
			e.UploaderID,
			e.UploadedAt.Format(time.RFC3339),
		)
	}
	return nil
}

func cmdPurgeExpired(db *sql.DB) error {
	n, err := PurgeExpiredBlobs(db)
	if err != nil {
		return err
	}
	fmt.Printf("Purged %d expired blob(s).\n", n)
	return nil
}

func cmdPurgeInactive(db *sql.DB, hours int) error {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	res, err := db.Exec(`DELETE FROM rv_blobs WHERE exp < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("purging inactive blobs: %w", err)
	}
	n, _ := res.RowsAffected()
	fmt.Printf("Purged %d inactive blob(s) (older than %d hours).\n", n, hours)
	return nil
}

func cmdPurgeByUploader(db *sql.DB, uploaderID string) error {
	// Get GUIDs uploaded by this uploader from audit, then delete from rv_blobs
	rows, err := db.Query(`SELECT DISTINCT guid FROM rv_blob_audit WHERE uploader_id = ?`, uploaderID)
	if err != nil {
		return fmt.Errorf("querying blobs by uploader: %w", err)
	}
	defer rows.Close()

	var count int64
	for rows.Next() {
		var guid []byte
		if err := rows.Scan(&guid); err != nil {
			return fmt.Errorf("scanning guid: %w", err)
		}
		res, err := db.Exec(`DELETE FROM rv_blobs WHERE guid = ?`, guid)
		if err != nil {
			return fmt.Errorf("deleting blob: %w", err)
		}
		n, _ := res.RowsAffected()
		count += n
	}
	if err := rows.Err(); err != nil {
		return err
	}
	fmt.Printf("Purged %d blob(s) uploaded by %s.\n", count, uploaderID)
	return nil
}
