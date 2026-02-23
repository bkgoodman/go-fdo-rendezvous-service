#!/bin/bash
# Test: Token auth mode — TO0 requires Bearer token, TO1 passes through

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

PORT=8182
CONFIG="$TEST_DATA_DIR/token-test.yaml"
DB_PATH="$TEST_DATA_DIR/token-test.db"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        stop_server "$SERVER_PID" "token-test"
    fi
    rm -f "$DB_PATH" "$DB_PATH"-* "$CONFIG" 2>/dev/null || true
}
trap cleanup EXIT

# ============================================================
log_info "=== Token Mode Test ==="
# ============================================================

init_test_env
cleanup_test_env
check_binary || exit 1

gen_config "$DB_PATH" "$PORT" "token" > "$CONFIG"

# Initialize DB and add a token
"$BINARY" -config "$CONFIG" -init-only
"$BINARY" -config "$CONFIG" -add-token "test-secret-token test-desc 720"

# Start server
SERVER_PID=$(start_server "$CONFIG" "$PORT" "token-test")
if [ -z "$SERVER_PID" ]; then
    log_error "Failed to start server"
    exit 1
fi

# ============================================================
# Test 1: TO0 without token → 401
# ============================================================
test_to0_no_token() {
    log_info "Test: TO0 without token returns 401"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Content-Type: application/cbor" \
        -d "" \
        "http://localhost:$PORT/fdo/101/msg/20")

    assert_equals "401" "$http_code" "TO0 without token should return 401"
}

# ============================================================
# Test 2: TO0 with invalid token → 401
# ============================================================
test_to0_invalid_token() {
    log_info "Test: TO0 with invalid token returns 401"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Content-Type: application/cbor" \
        -H "Authorization: Bearer wrong-token" \
        -d "" \
        "http://localhost:$PORT/fdo/101/msg/20")

    assert_equals "401" "$http_code" "TO0 with invalid token should return 401"
}

# ============================================================
# Test 3: TO0 with valid token → not 401 (passes auth, may get protocol error)
# ============================================================
test_to0_valid_token() {
    log_info "Test: TO0 with valid token passes auth"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Content-Type: application/cbor" \
        -H "Authorization: Bearer test-secret-token" \
        -d "" \
        "http://localhost:$PORT/fdo/101/msg/20")

    if [ "$http_code" != "401" ]; then
        log_success "TO0 with valid token passes auth (HTTP $http_code)"
        ((TESTS_PASSED++))
    else
        log_error "TO0 with valid token should not return 401"
        ((TESTS_FAILED++))
    fi
}

# ============================================================
# Test 4: TO1 without token → passes through (not 401)
# ============================================================
test_to1_no_token() {
    log_info "Test: TO1 without token passes through"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Content-Type: application/cbor" \
        -d "" \
        "http://localhost:$PORT/fdo/101/msg/30")

    if [ "$http_code" != "401" ]; then
        log_success "TO1 without token passes through (HTTP $http_code)"
        ((TESTS_PASSED++))
    else
        log_error "TO1 should not require token (got 401)"
        ((TESTS_FAILED++))
    fi
}

# ============================================================
run_test "TO0 No Token" test_to0_no_token
run_test "TO0 Invalid Token" test_to0_invalid_token
run_test "TO0 Valid Token" test_to0_valid_token
run_test "TO1 No Token Passthrough" test_to1_no_token

print_summary
