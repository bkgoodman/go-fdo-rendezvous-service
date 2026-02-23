# FDO Rendezvous Server — Tutorial

Step-by-step walkthrough showing how to build, configure, and exercise the rendezvous server across all three auth modes.

## Prerequisites

- Go 1.21+
- `curl`
- `openssl` (for key generation)

## Step 1: Build

```bash
cd /var/bkgdata/go-fdo-rendevzous
git submodule update --init --recursive
go build -o fdo-rendezvous .
```

## Step 2: Open Mode (No Auth)

The simplest configuration — all TO0 requests are accepted.

```bash
# Create a minimal config
cat > /tmp/rv-open.yaml <<EOF
debug: true
server:
  addr: "localhost:8080"
database:
  path: "/tmp/rv-open.db"
auth:
  mode: "open"
rv:
  replacement_policy: "allow-any"
  max_ttl: 86400
EOF

# Initialize DB
./fdo-rendezvous -config /tmp/rv-open.yaml -init-only
# Output: "Database initialized successfully"

# Start the server
./fdo-rendezvous -config /tmp/rv-open.yaml &
RV_PID=$!
sleep 1

# Verify it responds to FDO TO0 Hello (msg type 20)
# This will get a protocol error (empty body) but proves the endpoint works
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST \
  -H "Content-Type: application/cbor" \
  http://localhost:8080/fdo/101/msg/20
# Expected: HTTP 500 (protocol error, not 404)

# Verify TO1 HelloRV (msg type 30) also responds
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST \
  -H "Content-Type: application/cbor" \
  http://localhost:8080/fdo/101/msg/30
# Expected: HTTP 500 (protocol error, not 404)

# Clean up
kill $RV_PID
rm -f /tmp/rv-open.db*
```

**What happened**: The server started with open auth, created its SQLite database, and accepted connections on the FDO protocol endpoints. In production, an owner service would send properly-formatted CBOR TO0 messages to register blobs.

## Step 3: Token Mode

Requires a Bearer token for TO0. Devices doing TO1 don't need a token.

```bash
# Create config
cat > /tmp/rv-token.yaml <<EOF
debug: true
server:
  addr: "localhost:8080"
database:
  path: "/tmp/rv-token.db"
auth:
  mode: "token"
rv:
  replacement_policy: "allow-any"
  max_ttl: 86400
EOF

# Initialize DB
./fdo-rendezvous -config /tmp/rv-token.yaml -init-only

# Add an auth token (expires in 720 hours = 30 days)
./fdo-rendezvous -config /tmp/rv-token.yaml -add-token "my-secret-token owner-service 720"
# Output: "Token added: my-secret-token"

# List tokens to verify
./fdo-rendezvous -config /tmp/rv-token.yaml -list-tokens
# Shows: TOKEN, DESCRIPTION, EXPIRES, CREATED

# Start server
./fdo-rendezvous -config /tmp/rv-token.yaml &
RV_PID=$!
sleep 1

# TO0 without token → 401 Unauthorized
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST \
  -H "Content-Type: application/cbor" \
  http://localhost:8080/fdo/101/msg/20
# Expected: HTTP 401

# TO0 with wrong token → 401
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST \
  -H "Content-Type: application/cbor" \
  -H "Authorization: Bearer wrong-token" \
  http://localhost:8080/fdo/101/msg/20
# Expected: HTTP 401

# TO0 with valid token → passes auth (gets protocol error, but not 401)
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST \
  -H "Content-Type: application/cbor" \
  -H "Authorization: Bearer my-secret-token" \
  http://localhost:8080/fdo/101/msg/20
# Expected: HTTP 500 (protocol error, NOT 401)

# TO1 without any token → passes through (device auth is protocol-native)
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST \
  -H "Content-Type: application/cbor" \
  http://localhost:8080/fdo/101/msg/30
# Expected: HTTP 500 (NOT 401)

# Clean up
kill $RV_PID
rm -f /tmp/rv-token.db*
```

**What happened**: The middleware checked the `Authorization: Bearer` header on TO0 messages only. TO1 messages passed through because device authentication happens inside the FDO protocol itself.

## Step 4: Signatory Mode with PEM Key

Only vouchers signed by pre-enrolled keys are accepted.

```bash
# Generate a test key pair
openssl ecparam -genkey -name secp384r1 -noout -out /tmp/owner-priv.pem
openssl ec -in /tmp/owner-priv.pem -pubout -out /tmp/owner-pub.pem 2>/dev/null

# Create config
cat > /tmp/rv-sig.yaml <<EOF
debug: true
server:
  addr: "localhost:8080"
database:
  path: "/tmp/rv-sig.db"
auth:
  mode: "signatory"
rv:
  replacement_policy: "allow-any"
  max_ttl: 86400
EOF

# Initialize and enroll the key
./fdo-rendezvous -config /tmp/rv-sig.yaml -init-only
./fdo-rendezvous -config /tmp/rv-sig.yaml -enroll-key /tmp/owner-pub.pem
# Output: "Key enrolled: id=1 fingerprint=abcdef..."

# List enrolled keys
./fdo-rendezvous -config /tmp/rv-sig.yaml -list-keys
# Shows: ID, TYPE, FINGERPRINT, DID URI, LAST RESOLVED, DESCRIPTION

# Clean up
rm -f /tmp/rv-sig.db* /tmp/owner-priv.pem /tmp/owner-pub.pem
```

**What happened**: The public key was enrolled. When the server runs in signatory mode, the `AcceptVoucher` callback extracts the owner key from each TO0 voucher and checks its fingerprint against the enrolled keys table.

## Step 5: Admin CLI Overview

All admin commands work offline (no server running needed):

```bash
# Token management
./fdo-rendezvous -config config.yaml -add-token "tok1 my-service 720"
./fdo-rendezvous -config config.yaml -list-tokens
./fdo-rendezvous -config config.yaml -delete-token tok1
./fdo-rendezvous -config config.yaml -cleanup-expired-tokens

# Key enrollment
./fdo-rendezvous -config config.yaml -enroll-key /path/to/key.pem
./fdo-rendezvous -config config.yaml -enroll-did "did:web:example.com"
./fdo-rendezvous -config config.yaml -list-keys
./fdo-rendezvous -config config.yaml -delete-key 1

# Blob management
./fdo-rendezvous -config config.yaml -list-blobs
./fdo-rendezvous -config config.yaml -purge-expired
./fdo-rendezvous -config config.yaml -purge-inactive 168
```

## Running the Integration Tests

```bash
# Build first
go build -o fdo-rendezvous .

# Run individual tests
./tests/test-open-mode.sh
./tests/test-token-mode.sh
./tests/test-admin-cli.sh

# Run unit tests
go test -v ./...
```

## Troubleshooting

- **"file is not a database"** — Wrong or missing database password. Delete the `.db` file and re-initialize.
- **Server won't start** — Check if the port is in use: `ss -tlnp | grep 8080`
- **401 in open mode** — Verify `auth.mode` is set to `"open"` in your config file.
- **DID enrollment fails** — Ensure the DID document is served over HTTPS (or set `did.insecure_http: true` for development).
