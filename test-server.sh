#!/bin/bash

# Test script for Stellar Remote Signer Server
# This script tests all endpoints of the server

set -e

HOST="${HOST:-localhost}"
PORT="${PORT:-5003}"
BASE_URL="http://${HOST}:${PORT}"
BEARER_TOKEN="${BEARER_TOKEN:-987654321}"

echo "Testing Stellar Remote Signer Server"
echo "====================================="
echo "Base URL: ${BASE_URL}"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print test result
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $2"
    else
        echo -e "${RED}✗ FAIL${NC}: $2"
        exit 1
    fi
}

# Test 1: Health check
echo "Test 1: Health Check"
response=$(curl -s -w "\n%{http_code}" "${BASE_URL}/health")
http_code=$(echo "$response" | tail -n 1)
body=$(echo "$response" | head -n -1)

if [ "$http_code" = "200" ] && echo "$body" | grep -q "ok"; then
    print_result 0 "Health check endpoint"
else
    print_result 1 "Health check endpoint (got HTTP $http_code)"
fi
echo ""

# Test 2: Stellar TOML
echo "Test 2: Stellar TOML"
response=$(curl -s -w "\n%{http_code}" "${BASE_URL}/.well-known/stellar.toml")
http_code=$(echo "$response" | tail -n 1)
body=$(echo "$response" | head -n -1)

if [ "$http_code" = "200" ] && echo "$body" | grep -q "SIGNING_KEY"; then
    print_result 0 "Stellar TOML endpoint"
else
    print_result 1 "Stellar TOML endpoint (got HTTP $http_code)"
fi
echo ""

# Test 3: Sign endpoint - missing auth
echo "Test 3: Sign endpoint - authentication required"
response=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/sign-sep-10" \
    -H "Content-Type: application/json" \
    -d '{"transaction": "test", "network_passphrase": "Test"}')
http_code=$(echo "$response" | tail -n 1)

if [ "$http_code" = "401" ]; then
    print_result 0 "Sign endpoint rejects unauthenticated requests"
else
    print_result 1 "Sign endpoint authentication (got HTTP $http_code, expected 401)"
fi
echo ""

# Test 4: Sign endpoint - missing transaction
echo "Test 4: Sign endpoint - validation"
response=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/sign-sep-10" \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"network_passphrase": "Test"}')
http_code=$(echo "$response" | tail -n 1)

if [ "$http_code" = "400" ]; then
    print_result 0 "Sign endpoint validates missing transaction"
else
    print_result 1 "Sign endpoint validation (got HTTP $http_code, expected 400)"
fi
echo ""

# Test 5: Sign45 endpoint - missing auth
echo "Test 5: Sign45 endpoint - authentication required"
response=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/sign-sep-45" \
    -H "Content-Type: application/json" \
    -d '{"authorization_entries": "test", "network_passphrase": "Test"}')
http_code=$(echo "$response" | tail -n 1)

if [ "$http_code" = "401" ]; then
    print_result 0 "Sign45 endpoint rejects unauthenticated requests"
else
    print_result 1 "Sign45 endpoint authentication (got HTTP $http_code, expected 401)"
fi
echo ""

# Test 6: Sign45 endpoint - missing entries
echo "Test 6: Sign45 endpoint - validation"
response=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/sign-sep-45" \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"network_passphrase": "Test"}')
http_code=$(echo "$response" | tail -n 1)

if [ "$http_code" = "400" ]; then
    print_result 0 "Sign45 endpoint validates missing authorization_entries"
else
    print_result 1 "Sign45 endpoint validation (got HTTP $http_code, expected 400)"
fi
echo ""

# Test 7: Method not allowed
echo "Test 7: Method validation"
response=$(curl -s -w "\n%{http_code}" -X GET "${BASE_URL}/sign-sep-10")
http_code=$(echo "$response" | tail -n 1)

if [ "$http_code" = "405" ]; then
    print_result 0 "Endpoints reject wrong HTTP methods"
else
    print_result 1 "Method validation (got HTTP $http_code, expected 405)"
fi
echo ""

echo "====================================="
echo -e "${GREEN}All tests passed!${NC}"
echo ""
echo "Server is running correctly and responding to all endpoints."
echo "You can now use the server for SEP-10 and SEP-45 signing."
