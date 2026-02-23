#!/bin/bash
# Test: Open auth mode — server starts, accepts FDO messages, health check

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

PORT=8181
CONFIG="$TEST_DATA_DIR/open-test.yaml"
DB_PATH="$TEST_DATA_DIR/open-test.db"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        stop_server "$SERVER_PID" "open-test"
    fi
    rm -f "$DB_PATH" "$DB_PATH"-* "$CONFIG" 2>/dev/null || true
}
trap cleanup EXIT

# ============================================================
log_info "=== Open Mode Test ==="
# ============================================================

init_test_env
cleanup_test_env
check_binary || exit 1

gen_config "$DB_PATH" "$PORT" "open" > "$CONFIG"

# ============================================================
# Test 1: Server starts in open mode
# ============================================================
test_server_starts() {
    log_info "Test: Server starts in open mode"
    SERVER_PID=$(start_server "$CONFIG" "$PORT" "open-test")
    if [ -z "$SERVER_PID" ]; then
        log_error "Failed to start server"
        return 1
    fi
    log_success "Server started in open mode"
    ((TESTS_PASSED++))
}

# ============================================================
# Test 2: FDO endpoint responds (TO0 Hello = msg 20)
# ============================================================
test_fdo_endpoint_responds() {
    log_info "Test: FDO endpoint responds to POST"

    # Send a POST to TO0 Hello endpoint — should get a CBOR error (bad request)
    # but NOT a 404, proving the endpoint exists
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Content-Type: application/cbor" \
        -d "" \
        "http://localhost:$PORT/fdo/101/msg/20")

    # 400 or 500 means endpoint exists; 404 means it doesn't
    if [ "$http_code" != "404" ] && [ "$http_code" != "000" ]; then
        log_success "FDO TO0 endpoint responds (HTTP $http_code)"
        ((TESTS_PASSED++))
    else
        log_error "FDO TO0 endpoint not found (HTTP $http_code)"
        ((TESTS_FAILED++))
    fi
}

# ============================================================
# Test 3: TO1 endpoint responds (TO1 HelloRV = msg 30)
# ============================================================
test_to1_endpoint_responds() {
    log_info "Test: TO1 endpoint responds"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Content-Type: application/cbor" \
        -d "" \
        "http://localhost:$PORT/fdo/101/msg/30")

    if [ "$http_code" != "404" ] && [ "$http_code" != "000" ]; then
        log_success "FDO TO1 endpoint responds (HTTP $http_code)"
        ((TESTS_PASSED++))
    else
        log_error "FDO TO1 endpoint not found (HTTP $http_code)"
        ((TESTS_FAILED++))
    fi
}

# ============================================================
# Test 4: Non-FDO paths return 404
# ============================================================
test_non_fdo_404() {
    log_info "Test: Non-FDO path returns 404/405"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$PORT/")

    if [ "$http_code" = "404" ] || [ "$http_code" = "405" ]; then
        log_success "Non-FDO path returns $http_code"
        ((TESTS_PASSED++))
    else
        log_error "Non-FDO path returned $http_code (expected 404 or 405)"
        ((TESTS_FAILED++))
    fi
}

# ============================================================
# Test 5: No auth required in open mode (TO0 msg without Bearer)
# ============================================================
test_no_auth_required() {
    log_info "Test: No auth required for TO0 in open mode"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Content-Type: application/cbor" \
        -d "" \
        "http://localhost:$PORT/fdo/101/msg/20")

    # Should NOT be 401 (no auth required)
    if [ "$http_code" != "401" ]; then
        log_success "TO0 does not require auth in open mode (HTTP $http_code)"
        ((TESTS_PASSED++))
    else
        log_error "TO0 returned 401 in open mode (should not require auth)"
        ((TESTS_FAILED++))
    fi
}

# ============================================================
run_test "Server Starts" test_server_starts
run_test "FDO TO0 Endpoint" test_fdo_endpoint_responds
run_test "FDO TO1 Endpoint" test_to1_endpoint_responds
run_test "Non-FDO 404" test_non_fdo_404
run_test "No Auth Required" test_no_auth_required

print_summary
