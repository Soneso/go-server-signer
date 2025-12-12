# Stellar Remote Signer

Production-ready Go server for remote signing of SEP-10 and SEP-45 client domain authentication requests.

## Overview

This server implements remote signing capabilities for Stellar authentication protocols:

- **SEP-10**: Web Authentication - Signs transaction envelopes for user authentication
- **SEP-45**: Web Authentication for Soroban Contracts - Signs authorization entries for contract-based authentication

## Features

- SEP-10 transaction signing endpoint
- SEP-45 authorization entries signing endpoint
- Stellar TOML serving
- Bearer token authentication
- CORS support
- Graceful shutdown
- Health check endpoint
- Configuration via JSON file or environment variables

## Requirements

- Go 1.21 or later

## Installation

Clone the repository and install dependencies:

```bash
git clone <repository-url>
cd go-server-signer
go mod download
```

## Configuration

The server can be configured using either a JSON configuration file or environment variables.

### Configuration File

Create a `config.json` file (see `config.example.json`):

```json
{
  "host": "0.0.0.0",
  "port": 5003,
  "account_id": "GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV",
  "secret": "SBRSOOURG2E24VGDR6NKZJMBOSOHVT6GV7EECUR3ZBE7LGSSVYN5VMOG",
  "network_passphrase": "Test SDF Network ; September 2015",
  "soroban_rpc_url": "https://soroban-testnet.stellar.org",
  "bearer_token": "987654321"
}
```

### Environment Variables

Alternatively, set these environment variables (see `.env.example`):

```bash
export HOST=0.0.0.0
export PORT=5003
export ACCOUNT_ID=GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV
export SECRET=SBRSOOURG2E24VGDR6NKZJMBOSOHVT6GV7EECUR3ZBE7LGSSVYN5VMOG
export NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
export SOROBAN_RPC_URL="https://soroban-testnet.stellar.org"
export BEARER_TOKEN=987654321
```

## Building

Build the server:

```bash
go build -o go-server-signer ./cmd/server
```

Or use the provided Makefile:

```bash
make build
```

## Running

### With Configuration File

```bash
./go-server-signer -config config.json
```

### With Environment Variables

```bash
./go-server-signer
```

### Direct with Go

```bash
go run ./cmd/server -config config.json
```

## API Reference

### GET /health

Health check endpoint.

**Authentication:** Not required

**Response:**
```json
{
  "status": "ok"
}
```

**Example:**
```bash
curl http://localhost:5003/health
```

### GET /.well-known/stellar.toml

Returns the Stellar TOML file with the signing key.

**Authentication:** Not required

**Response:**
```toml
ACCOUNTS = ["GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV"]
SIGNING_KEY = "GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV"
NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"
```

**Example:**
```bash
curl http://localhost:5003/.well-known/stellar.toml
```

### POST /sign-sep-10

Signs a SEP-10 transaction envelope.

**Authentication:** Required (Bearer token)

**Request:**
```json
{
  "transaction": "<base64 XDR envelope>",
  "network_passphrase": "Test SDF Network ; September 2015"
}
```

**Response:**
```json
{
  "transaction": "<signed base64 XDR envelope>",
  "network_passphrase": "Test SDF Network ; September 2015"
}
```

**Example:**
```bash
curl -X POST http://localhost:5003/sign-sep-10 \
  -H "Authorization: Bearer 987654321" \
  -H "Content-Type: application/json" \
  -d '{
    "transaction": "AAAAAgAAAAD...",
    "network_passphrase": "Test SDF Network ; September 2015"
  }'
```

### POST /sign-sep-45

Signs a single SEP-45 authorization entry for client domain verification.

**Authentication:** Required (Bearer token)

**Request:**
```json
{
  "authorization_entry": "<base64 XDR of single SorobanAuthorizationEntry>",
  "network_passphrase": "Test SDF Network ; September 2015"
}
```

**Response:**
```json
{
  "authorization_entry": "<signed base64 XDR of single SorobanAuthorizationEntry>",
  "network_passphrase": "Test SDF Network ; September 2015"
}
```

**Validation:**
The server validates that the authorization entry's address matches the server's signing key. If it doesn't match, an error is returned:
```json
{
  "error": "entry address does not match signing key"
}
```

**Example:**
```bash
curl -X POST http://localhost:5003/sign-sep-45 \
  -H "Authorization: Bearer 987654321" \
  -H "Content-Type: application/json" \
  -d '{
    "authorization_entry": "AAAAAgAAAAD...",
    "network_passphrase": "Test SDF Network ; September 2015"
  }'
```

## Security Notes

- Store secrets securely (use environment variables or secure secret management)
- Use HTTPS in production
- Implement rate limiting
- Rotate bearer tokens regularly
- Use strong, randomly generated bearer tokens
- Monitor and log authentication failures
- Consider implementing IP whitelisting

## Testing

Run the unit tests:

```bash
go test ./...
```

Run tests with coverage:

```bash
go test -cover ./...
```

Run tests with race detector:

```bash
go test -race ./...
```

Or use the Makefile:

```bash
make test
make test-coverage
make test-race
```

## Project Structure

```
.
├── cmd/
│   └── server/          # Main application entry point
│       └── main.go
├── internal/
│   ├── config/          # Configuration management
│   │   └── config.go
│   ├── handler/         # HTTP handlers
│   │   ├── handler.go
│   │   └── handler_test.go
│   └── signer/          # Signing logic
│       ├── sep10.go
│       ├── sep10_test.go
│       ├── sep45.go
│       └── sep45_test.go
├── .gitignore
├── .env.example
├── config.example.json
├── Dockerfile
├── docker-compose.yml
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## Error Handling

All endpoints return appropriate HTTP status codes:

- `200 OK` - Successful operation
- `400 Bad Request` - Invalid request parameters or malformed data
- `401 Unauthorized` - Missing or invalid authentication
- `405 Method Not Allowed` - Wrong HTTP method used
- `500 Internal Server Error` - Server error

Error responses include a JSON body with error details:

```json
{
  "error": "error message"
}
```

## SEP-45 Signing Details

The SEP-45 signing process involves:

1. Decoding the base64 XDR of a single `SorobanAuthorizationEntry` object
2. Validating that the entry's address matches the signer's account ID
3. Setting the `signature_expiration_ledger` to current ledger + 10
4. Building a `HashIdPreimage` with type `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` containing:
   - `network_id` (SHA256 hash of network passphrase)
   - `nonce` from address credentials
   - `signature_expiration_ledger` (current ledger + 10)
   - `root_invocation` from the entry
5. Computing SHA256 hash of the preimage
6. Signing the hash with the keypair
7. Setting the signature as an `SCVal` Vec containing a Map with `public_key` and `signature` bytes
8. Encoding the signed entry back to base64 XDR

## Production Deployment

For production deployment:

1. Build the binary with optimizations:
   ```bash
   CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w -s' -o go-server-signer ./cmd/server
   ```

2. Use a process manager (systemd, supervisor, or Docker)

3. Configure reverse proxy (nginx, caddy) with HTTPS

4. Set up monitoring and logging

5. Implement rate limiting at the reverse proxy level

6. Use secure secret management (HashiCorp Vault, AWS Secrets Manager, etc.)

## Docker

Build and run with Docker:

```bash
docker build -t stellar-remote-signer .
docker run -p 5003:5003 \
  -e ACCOUNT_ID=GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV \
  -e SECRET=SBRSOOURG2E24VGDR6NKZJMBOSOHVT6GV7EECUR3ZBE7LGSSVYN5VMOG \
  -e BEARER_TOKEN=987654321 \
  stellar-remote-signer
```

Or use Docker Compose:

```bash
docker-compose up
```

## License

Apache 2.0

## References

- [SEP-10 Specification](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md)
- [SEP-45 Specification](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0045.md)
- [Stellar Go SDK](https://github.com/stellar/go)
