# Prompt for Deploying Go Server Signer

Use this prompt for an agent on a remote server to understand and deploy this project.

---

## Project Overview

This is a Go server that provides client domain signing for Stellar SEP-10 and SEP-45 authentication protocols. It allows non-custodial wallets to prove ownership of a domain during the Stellar web authentication flow.

**Use Case:** When a wallet authenticates with a Stellar anchor (like an exchange), the anchor may require proof that the wallet is associated with a specific domain. This server signs the authentication challenge on behalf of that domain.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check, returns `{"status":"ok"}` |
| `/.well-known/stellar.toml` | GET | Returns Stellar TOML with SIGNING_KEY |
| `/sign-sep-10` | POST | Signs SEP-10 transaction envelopes |
| `/sign-sep-45` | POST | Signs SEP-45 authorization entries |

All signing endpoints require `Authorization: Bearer <token>` header.

## Deployment Steps

### 1. Prerequisites
- Go 1.21 or higher
- HTTPS certificate (Let's Encrypt recommended)
- Reverse proxy (nginx or caddy) for HTTPS termination

### 2. Clone and Build
```bash
git clone https://github.com/[USERNAME]/[REPO].git
cd [REPO]
go build -o bin/go-server-signer ./cmd/server
```

### 3. Create Production Config

Create `config.json`:
```json
{
  "account_id": "GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV",
  "secret": "SBRSOOURG2E24VGDR6NKZJMBOSOHVT6GV7EECUR3ZBE7LGSSVYN5VMOG",
  "bearer_token": "YOUR_SECURE_TOKEN_HERE",
  "network_passphrase": "Test SDF Network ; September 2015",
  "port": 5003,
  "soroban_rpc_url": "https://soroban-testnet.stellar.org"
}
```

**Important:** For production, generate a secure bearer token and consider using a dedicated keypair.

### 4. Run the Server
```bash
./bin/go-server-signer -config config.json
```

Or with environment variables:
```bash
export ACCOUNT_ID="GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV"
export SECRET="SBRSOOURG2E24VGDR6NKZJMBOSOHVT6GV7EECUR3ZBE7LGSSVYN5VMOG"
export BEARER_TOKEN="YOUR_SECURE_TOKEN_HERE"
export NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
export PORT="5003"
export SOROBAN_RPC_URL="https://soroban-testnet.stellar.org"
./bin/go-server-signer
```

### 5. Set Up Reverse Proxy (nginx example)

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5003;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 6. Run as Systemd Service

Create `/etc/systemd/system/go-server-signer.service`:
```ini
[Unit]
Description=Stellar Server Signer
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/go-server-signer
ExecStart=/path/to/go-server-signer/bin/go-server-signer -config /path/to/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable go-server-signer
sudo systemctl start go-server-signer
```

### 7. Verify Deployment

```bash
# Health check
curl https://your-domain.com/health

# Stellar TOML
curl https://your-domain.com/.well-known/stellar.toml

# Should return:
# ACCOUNTS = ["GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV"]
# SIGNING_KEY = "GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV"
# NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"
```

## Docker Deployment (Alternative)

```bash
# Build image
docker build -t go-server-signer .

# Run container
docker run -d \
  --name go-server-signer \
  -p 5003:5003 \
  -e ACCOUNT_ID="GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV" \
  -e SECRET="SBRSOOURG2E24VGDR6NKZJMBOSOHVT6GV7EECUR3ZBE7LGSSVYN5VMOG" \
  -e BEARER_TOKEN="YOUR_SECURE_TOKEN_HERE" \
  -e NETWORK_PASSPHRASE="Test SDF Network ; September 2015" \
  -e SOROBAN_RPC_URL="https://soroban-testnet.stellar.org" \
  go-server-signer
```

## Security Considerations

1. **Bearer Token:** Use a strong, random token for production
2. **Secret Key:** Keep the Stellar secret key secure, consider using secrets management
3. **HTTPS:** Always use HTTPS in production
4. **Firewall:** Restrict access to port 5003 to only the reverse proxy
5. **Logging:** Monitor logs for unauthorized access attempts

## API Usage Examples

### SEP-10 Signing
```bash
curl -X POST https://your-domain.com/sign-sep-10 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "transaction": "BASE64_XDR_ENVELOPE",
    "network_passphrase": "Test SDF Network ; September 2015"
  }'
```

### SEP-45 Signing
```bash
curl -X POST https://your-domain.com/sign-sep-45 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "authorization_entries": "BASE64_XDR_ARRAY",
    "network_passphrase": "Test SDF Network ; September 2015"
  }'
```

## Troubleshooting

1. **"Failed to get current ledger"** - Check SOROBAN_RPC_URL is accessible
2. **"Unauthenticated"** - Verify bearer token matches config
3. **"Invalid XDR"** - Check the base64-encoded data is valid
4. **Connection refused** - Ensure server is running and port is correct
