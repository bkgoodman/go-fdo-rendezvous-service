#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0

set -euo pipefail

# Source test library
source "$(dirname "$0")/lib.sh"

# Test scripts to run
TESTS=(
    "test-admin-cli.sh"
    "test-open-mode.sh"
    "test-token-mode.sh"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info "Starting all rendezvous server tests..."

# Track overall results
TOTAL_ASSERTIONS=0
TOTAL_PASSED=0
TOTAL_FAILED=0

# Run each test script
for test_script in "${TESTS[@]}"; do
    log_info "Running test suite: $test_script"
    echo
    
    # Run the test and capture its output
    if bash "$(dirname "$0")/$test_script" 2>&1; then
        log_info "✓ $test_script PASSED"
    else
        log_error "✗ $test_script FAILED"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
    echo
done

# Run unit tests
log_info "Running unit tests..."
echo
if go test -v -count=1 -timeout 60s ./... 2>&1; then
    log_info "✓ Unit tests PASSED"
else
    log_error "✗ Unit tests FAILED"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
fi
echo

# Summary
log_info "All tests completed"
echo "======================================="
if [ $TOTAL_FAILED -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}SOME TESTS FAILED${NC}"
    echo "Failed test suites: $TOTAL_FAILED"
    exit 1
fi
