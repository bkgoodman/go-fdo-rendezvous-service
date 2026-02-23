#!/bin/bash
# Common test utilities and helper functions for FDO Rendezvous Server

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_DATA_DIR="$SCRIPT_DIR/data"
BINARY="$PROJECT_ROOT/fdo-rendezvous"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

init_test_env() {
    mkdir -p "$TEST_DATA_DIR"
}

cleanup_test_env() {
    rm -f "$TEST_DATA_DIR"/*.db 2>/dev/null || true
    rm -f "$TEST_DATA_DIR"/*.db-* 2>/dev/null || true
    rm -f "$TEST_DATA_DIR"/*.yaml 2>/dev/null || true
    rm -f "$TEST_DATA_DIR"/*.pem 2>/dev/null || true
    rm -f "$TEST_DATA_DIR"/*.log 2>/dev/null || true
}

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_error()   { echo -e "${RED}[FAIL]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }

assert_equals() {
    local expected="$1" actual="$2" message="${3:-Assertion failed}"
    if [ "$expected" = "$actual" ]; then
        log_success "$message"
        ((TESTS_PASSED++))
        return 0
    else
        log_error "$message (expected: '$expected', got: '$actual')"
        ((TESTS_FAILED++))
        return 1
    fi
}

assert_not_empty() {
    local value="$1" message="${2:-Value should not be empty}"
    if [ -n "$value" ]; then
        log_success "$message"
        ((TESTS_PASSED++))
        return 0
    else
        log_error "$message"
        ((TESTS_FAILED++))
        return 1
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" message="${3:-Should contain substring}"
    if echo "$haystack" | grep -q "$needle"; then
        log_success "$message"
        ((TESTS_PASSED++))
        return 0
    else
        log_error "$message (output does not contain '$needle')"
        ((TESTS_FAILED++))
        return 1
    fi
}

assert_exit_code() {
    local expected="$1" actual="$2" message="${3:-Exit code check}"
    assert_equals "$expected" "$actual" "$message"
}

start_server() {
    local config="$1"
    local port="${2:-8080}"
    local instance_name="${3:-rv-server}"

    log_info "Starting $instance_name on port $port..." >&2

    "$BINARY" -config "$config" > "$TEST_DATA_DIR/${instance_name}.log" 2>&1 &
    local pid=$!

    # Wait for server to be ready
    local max_attempts=30
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if ! kill -0 $pid 2>/dev/null; then
            log_error "Failed to start $instance_name - process died" >&2
            tail -5 "$TEST_DATA_DIR/${instance_name}.log" 2>/dev/null | while IFS= read -r line; do log_error "  $line" >&2; done
            return 1
        fi
        if netstat -tlnp 2>/dev/null | grep -q ":$port " || ss -tlnp 2>/dev/null | grep -q ":$port "; then
            sleep 0.2
            log_success "$instance_name started (PID: $pid)" >&2
            echo "$pid"
            return 0
        fi
        sleep 0.5
        ((attempt++))
    done

    log_error "Failed to start $instance_name - timeout" >&2
    tail -10 "$TEST_DATA_DIR/${instance_name}.log" 2>/dev/null | while IFS= read -r line; do log_error "  $line" >&2; done
    kill $pid 2>/dev/null || true
    return 1
}

stop_server() {
    local pid="$1" instance_name="${2:-rv-server}"
    if [ -z "$pid" ]; then return 0; fi
    log_info "Stopping $instance_name (PID: $pid)..."
    kill $pid 2>/dev/null || true
    local attempt=0
    while [ $attempt -lt 10 ] && kill -0 $pid 2>/dev/null; do
        sleep 0.5
        ((attempt++))
    done
    kill -9 $pid 2>/dev/null || true
    log_success "$instance_name stopped"
}

run_test() {
    local test_name="$1" test_func="$2"
    echo ""
    echo "=========================================="
    echo "Running: $test_name"
    echo "=========================================="
    ((TESTS_RUN++))
    if $test_func; then
        log_success "Test completed: $test_name"
    else
        log_error "Test failed: $test_name"
    fi
}

print_summary() {
    echo ""
    echo "======================================"
    echo "Test Summary"
    echo "======================================"
    echo "Total assertions: $((TESTS_PASSED + TESTS_FAILED))"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "${RED}Failed: $TESTS_FAILED${NC}"
        return 1
    else
        echo -e "${GREEN}Failed: 0${NC}"
        return 0
    fi
}

check_binary() {
    if [ ! -f "$BINARY" ]; then
        log_info "Binary not found, building..."
        (cd "$PROJECT_ROOT" && go build -o fdo-rendezvous .) || {
            log_error "Failed to build"
            return 1
        }
    fi
    return 0
}

# Generate a test config file
gen_config() {
    local db_path="$1" port="$2" auth_mode="${3:-open}"
    cat <<EOF
debug: true
server:
  addr: "localhost:$port"
database:
  path: "$db_path"
auth:
  mode: "$auth_mode"
rv:
  replacement_policy: "allow-any"
  max_ttl: 86400
EOF
}

export -f log_info log_success log_error log_warn
export -f assert_equals assert_not_empty assert_contains assert_exit_code
export -f start_server stop_server run_test print_summary check_binary
export -f init_test_env cleanup_test_env gen_config
export SCRIPT_DIR PROJECT_ROOT TEST_DATA_DIR BINARY
export RED GREEN YELLOW BLUE NC
