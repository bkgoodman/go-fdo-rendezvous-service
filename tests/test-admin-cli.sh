#!/bin/bash
# Test: Admin CLI commands (tokens, keys, blobs, purge)

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

PORT=8180
CONFIG="$TEST_DATA_DIR/admin-test.yaml"
DB_PATH="$TEST_DATA_DIR/admin-test.db"

cleanup() {
    rm -f "$DB_PATH" "$DB_PATH"-* "$CONFIG" 2>/dev/null || true
}
trap cleanup EXIT

# ============================================================
log_info "=== Admin CLI Test ==="
# ============================================================

init_test_env
cleanup
check_binary || exit 1

# Create config
gen_config "$DB_PATH" "$PORT" "open" > "$CONFIG"

# Initialize DB
"$BINARY" -config "$CONFIG" -init-only
assert_exit_code "0" "$?" "init-only should succeed"

# ============================================================
# Token management
# ============================================================
test_token_management() {
    log_info "Token Management"

    # Add tokens
    "$BINARY" -config "$CONFIG" -add-token "tok1 first-token 720"
    assert_exit_code "0" "$?" "add token tok1"

    "$BINARY" -config "$CONFIG" -add-token "tok2 second-token"
    assert_exit_code "0" "$?" "add token tok2 (no expiry)"

    # List tokens
    local output
    output=$("$BINARY" -config "$CONFIG" -list-tokens)
    assert_exit_code "0" "$?" "list tokens"
    assert_contains "$output" "tok1" "list should contain tok1"
    assert_contains "$output" "tok2" "list should contain tok2"
    assert_contains "$output" "first-token" "list should contain description"

    # Delete token
    "$BINARY" -config "$CONFIG" -delete-token "tok1"
    assert_exit_code "0" "$?" "delete tok1"

    output=$("$BINARY" -config "$CONFIG" -list-tokens)
    if echo "$output" | grep -q "tok1"; then
        log_error "tok1 should be deleted"
        ((TESTS_FAILED++))
    else
        log_success "tok1 deleted successfully"
        ((TESTS_PASSED++))
    fi

    # Cleanup expired (tok2 has no expiry, nothing to clean)
    "$BINARY" -config "$CONFIG" -cleanup-expired-tokens
    assert_exit_code "0" "$?" "cleanup expired tokens"
}

# ============================================================
# Key enrollment
# ============================================================
test_key_enrollment() {
    log_info "Key Enrollment"

    # Generate a test PEM key
    local key_file="$TEST_DATA_DIR/test-key.pem"
    openssl ecparam -genkey -name prime256v1 -noout 2>/dev/null | \
        openssl ec -pubout -out "$key_file" 2>/dev/null

    if [ ! -f "$key_file" ]; then
        log_warn "openssl not available, skipping PEM key enrollment test"
        return
    fi

    # Enroll key
    local output
    output=$("$BINARY" -config "$CONFIG" -enroll-key "$key_file")
    assert_exit_code "0" "$?" "enroll PEM key"
    assert_contains "$output" "fingerprint=" "should show fingerprint"

    # List keys
    output=$("$BINARY" -config "$CONFIG" -list-keys)
    assert_exit_code "0" "$?" "list keys"
    assert_contains "$output" "pem" "should show pem type"

    # Delete key by ID
    "$BINARY" -config "$CONFIG" -delete-key "1"
    assert_exit_code "0" "$?" "delete key by ID"

    output=$("$BINARY" -config "$CONFIG" -list-keys)
    assert_contains "$output" "No enrolled keys" "should be empty after delete"
}

# ============================================================
# Blob management
# ============================================================
test_blob_management() {
    log_info "Blob Management"

    # List blobs (should be empty)
    local output
    output=$("$BINARY" -config "$CONFIG" -list-blobs)
    assert_exit_code "0" "$?" "list blobs"
    assert_contains "$output" "No blob audit" "should be empty initially"

    # Purge expired (nothing to purge)
    "$BINARY" -config "$CONFIG" -purge-expired
    assert_exit_code "0" "$?" "purge expired (empty)"
}

# ============================================================
# Run all tests
# ============================================================
run_test "Token Management" test_token_management
run_test "Key Enrollment" test_key_enrollment
run_test "Blob Management" test_blob_management

print_summary
