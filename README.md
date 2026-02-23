# FDO Rendezvous Server

A standalone FIDO Device Onboard (FDO) Rendezvous Server handling TO0 (owner blob upload) and TO1 (device blob retrieval), with configurable authentication, DID:web key enrollment, and administrative CLI tooling.

## Overview

In the FDO protocol, the **Rendezvous Server (RV)** is the meeting point between device owners and devices. Owner services register their contact information via **TO0**, and devices discover where to connect via **TO1**. This server implements only those two protocols — it does not handle Device Initialization (DI) or Transfer of Ownership (TO2).

The server supports three authentication modes for TO0:

- **Open** — accept all TO0 requests (suitable for development/testing)
- **Token** — require HTTP `Authorization: Bearer` token
- **Signatory** — require the voucher's owner key to be pre-enrolled

## Quick Start

```bash
# Build
git submodule update --init --recursive
go build -o fdo-rendezvous .

# Initialize database (open mode, defaults)
./fdo-rendezvous -init-only

# Run server
./fdo-rendezvous -config config.yaml
```

## Setup

### Prerequisites

- Go 1.21 or later
- Git

### Installation

```bash
git clone <repository-url>
cd go-fdo-rendezvous
git submodule update --init --recursive
go build -o fdo-rendezvous .
```

## Configuration

Copy `config.yaml` and customize:

```bash
cp config.yaml my-config.yaml
./fdo-rendezvous -config my-config.yaml
```

### Configuration Reference

```yaml
debug: false

server:
  addr: "localhost:8080"    # Listen address
  ext_addr: ""              # External address (for proxied setups)
  use_tls: false

database:
  path: "rendezvous.db"    # SQLite database path
  password: ""              # Database encryption password (optional)

auth:
  mode: "open"              # "open", "token", or "signatory"

rv:
  replacement_policy: "allow-any"  # See Replacement Policies below
  max_ttl: 4294967295              # Max TTL cap (seconds)

did:
  refresh_hours: 24         # Lazy DID:web key refresh threshold
  insecure_http: false      # Allow HTTP for DID:web (dev only)

pruning:
  enabled: false
  inactive_hours: 720       # 30 days
  interval_minutes: 60
```

### Replacement Policies

Controls how the server handles TO0 registrations for an already-registered GUID:

| Policy | Description |
| --- | --- |
| `allow-any` | Any valid voucher can replace (default) |
| `mfg-consistency` | Only same manufacturer key can replace |
| `first-lock` | First registration locks until TTL expires |
| `owner-consistency` | Only same owner key can replace |

## Authentication Modes

### Open Mode (`auth.mode: "open"`)

All TO0 requests are accepted. TO1 always passes through (device authentication is protocol-native). Suitable for development and trusted networks.

### Token Mode (`auth.mode: "token"`)

TO0 requests require an HTTP `Authorization: Bearer <token>` header. Tokens are managed via CLI. TO1 passes through unauthenticated.

```bash
# Add a token (expires in 720 hours = 30 days)
./fdo-rendezvous -config config.yaml -add-token "my-secret-token description 720"

# List tokens
./fdo-rendezvous -config config.yaml -list-tokens

# Delete a token
./fdo-rendezvous -config config.yaml -delete-token my-secret-token

# Remove expired tokens
./fdo-rendezvous -config config.yaml -cleanup-expired-tokens
```

### Signatory Mode (`auth.mode: "signatory"`)

TO0 requests are accepted only if the voucher's owner public key (last entry in the voucher chain, or manufacturer key if no entries) matches a pre-enrolled key. Keys can be enrolled as PEM files or resolved from DID:web URIs.

```bash
# Enroll a PEM public key
./fdo-rendezvous -config config.yaml -enroll-key /path/to/owner-public.pem

# Enroll via DID:web (resolves key from DID document)
./fdo-rendezvous -config config.yaml -enroll-did "did:web:example.com:owner1"

# List enrolled keys
./fdo-rendezvous -config config.yaml -list-keys

# Delete an enrolled key (by ID or fingerprint)
./fdo-rendezvous -config config.yaml -delete-key 1
./fdo-rendezvous -config config.yaml -delete-key abcdef1234567890...
```

## DID:web Key Enrollment

When a key is enrolled via `did:web`, the server:

1. Resolves the DID document over HTTPS (or HTTP if `did.insecure_http` is set)
2. Extracts the public key from the first verification method
3. Stores the key, its SHA-256 fingerprint, and the DID URI
4. **Lazy refresh**: On subsequent TO0 requests, if the key hasn't been re-resolved within `did.refresh_hours`, a background goroutine re-fetches the DID document. If the key changed, the fingerprint is updated. The current request uses the cached fingerprint (best-effort, non-blocking).

## CLI Reference

### Server

```bash
./fdo-rendezvous -config config.yaml           # Start server
./fdo-rendezvous -config config.yaml -debug     # Start with debug logging
./fdo-rendezvous -config config.yaml -init-only  # Initialize DB and exit
```

### Token Management

```bash
-list-tokens                    List all auth tokens
-add-token "<token> [desc] [hours]"  Add token (hours = expiry)
-delete-token <token>           Delete a token
-cleanup-expired-tokens         Remove all expired tokens
```

### Key Enrollment

```bash
-enroll-key <pem-file>          Enroll PEM public key
-enroll-did <did:web:...>       Enroll DID:web key
-list-keys                      List enrolled keys
-delete-key <id-or-fingerprint> Delete enrolled key
```

### Blob Management

```bash
-list-blobs                     List blob audit entries
-list-blobs-by-uploader <id>    Filter by uploader
-purge-expired                  Remove expired blobs
-purge-inactive <hours>         Remove blobs inactive for N hours
-purge-by-uploader <id>         Remove blobs by uploader
```

## Pruning & Maintenance

Enable background pruning in config:

```yaml
pruning:
  enabled: true
  inactive_hours: 720       # Delete blobs not accessed in 30 days
  interval_minutes: 60      # Check every hour
```

Or run manual purges:

```bash
./fdo-rendezvous -config config.yaml -purge-expired
./fdo-rendezvous -config config.yaml -purge-inactive 168  # 7 days
```

## Integration with Other FDO Services

This server is designed to work with:

- **Manufacturing Station** (`go-fdo-di`) — creates vouchers with RV instructions pointing to this server
- **Onboarding Service** (`go-fdo-onboarding-service`) — registers blobs via TO0, then devices find it via TO1
- **Voucher Manager** (`go-fdo-voucher-managment`) — manages voucher supply chain, registers with RV via TO0
- **Device Client** (`go-fdo-endpoint`) — performs TO1 to discover onboarding service address

### Typical Flow

```text
1. Manufacturing: DI creates voucher with RV address → device + voucher
2. Owner Service: TO0 registers blob with RV → "device GUID X should go to owner at address Y"
3. Device Boot:   TO1 queries RV → "where should I go?" → gets owner address
4. Onboarding:    TO2 between device and owner service (not handled by RV)
```

## Running Tests

```bash
# Unit tests
go test -v ./...

# Integration tests (requires built binary)
go build -o fdo-rendezvous .
./tests/test-open-mode.sh
./tests/test-token-mode.sh
./tests/test-admin-cli.sh
```

## License

Apache 2.0
