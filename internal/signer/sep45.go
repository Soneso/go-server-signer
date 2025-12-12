package signer

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/stellar/go/keypair"
	"github.com/stellar/go/strkey"
	"github.com/stellar/go/xdr"
)

// rpcRequest represents a JSON-RPC request
type rpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// rpcResponse represents a JSON-RPC response for getLatestLedger
type rpcResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  struct {
		ID              string `json:"id"`
		ProtocolVersion int    `json:"protocolVersion"`
		Sequence        uint32 `json:"sequence"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// getLatestLedger fetches the latest ledger sequence from Soroban RPC
func getLatestLedger(rpcURL string) (uint32, error) {
	reqBody := rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "getLatestLedger",
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal RPC request: %w", err)
	}

	resp, err := http.Post(rpcURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, fmt.Errorf("failed to call Soroban RPC: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read RPC response: %w", err)
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return 0, fmt.Errorf("failed to unmarshal RPC response: %w", err)
	}

	if rpcResp.Error != nil {
		return 0, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	return rpcResp.Result.Sequence, nil
}

// SignSEP45AuthorizationEntries signs SEP-45 authorization entries
func SignSEP45AuthorizationEntries(entriesXDR, networkPassphrase, secretKey, rpcURL string) (string, error) {
	// Parse the keypair from secret
	kp, err := keypair.Parse(secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse secret key: %w", err)
	}

	fullKP, ok := kp.(*keypair.Full)
	if !ok {
		return "", fmt.Errorf("secret key is not a full keypair")
	}

	clientDomainAccount := fullKP.Address()

	// Get raw public key bytes using strkey.Decode
	rawPublicKey, err := strkey.Decode(strkey.VersionByteAccountID, clientDomainAccount)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// Decode base64 XDR array of SorobanAuthorizationEntry
	xdrBytes, err := base64.StdEncoding.DecodeString(entriesXDR)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Read array length (first 4 bytes, big-endian unsigned int)
	if len(xdrBytes) < 4 {
		return "", fmt.Errorf("invalid XDR: too short to contain array length")
	}

	count := binary.BigEndian.Uint32(xdrBytes[:4])
	if count == 0 {
		return "", fmt.Errorf("no authorization entries found")
	}

	// Parse each entry using bytes.Reader
	entries := make([]xdr.SorobanAuthorizationEntry, 0, count)
	reader := bytes.NewReader(xdrBytes[4:])

	for i := uint32(0); i < count; i++ {
		var entry xdr.SorobanAuthorizationEntry
		_, err := xdr.Unmarshal(reader, &entry)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal entry %d: %w", i, err)
		}
		entries = append(entries, entry)
	}

	// Calculate network ID (SHA256 hash of network passphrase)
	networkIDBytes := sha256.Sum256([]byte(networkPassphrase))
	var networkID xdr.Hash
	copy(networkID[:], networkIDBytes[:])

	// Fetch current ledger from Soroban RPC
	currentLedger, err := getLatestLedger(rpcURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch current ledger: %w", err)
	}

	// Find and sign the client domain entry
	for i := range entries {
		entry := &entries[i]

		// Check if this entry uses address credentials
		if entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddress {
			continue
		}

		addrCreds := entry.Credentials.Address
		if addrCreds == nil {
			continue
		}

		// Get the address as string
		if addrCreds.Address.Type != xdr.ScAddressTypeScAddressTypeAccount {
			continue
		}

		// Extract the account ID from the address
		accountID := addrCreds.Address.AccountId
		if accountID == nil {
			continue
		}

		entryAccount, err := strkey.Encode(strkey.VersionByteAccountID, accountID.Ed25519[:])
		if err != nil {
			continue
		}

		// Check if this is the client domain entry
		if entryAccount != clientDomainAccount {
			continue
		}

		// Set signature expiration ledger to current ledger + 10
		addrCreds.SignatureExpirationLedger = xdr.Uint32(currentLedger + 10)

		// Build preimage for signing
		preimage := xdr.HashIdPreimage{
			Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
			SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
				NetworkId:                 networkID,
				Nonce:                     addrCreds.Nonce,
				SignatureExpirationLedger: addrCreds.SignatureExpirationLedger,
				Invocation:                entry.RootInvocation,
			},
		}

		// Marshal preimage to bytes
		preimageBytes, err := preimage.MarshalBinary()
		if err != nil {
			return "", fmt.Errorf("failed to marshal preimage: %w", err)
		}

		// Hash the preimage
		payload := sha256.Sum256(preimageBytes)

		// Sign the hash
		signature, err := fullKP.Sign(payload[:])
		if err != nil {
			return "", fmt.Errorf("failed to sign payload: %w", err)
		}

		// Build signature entry as Map with public_key and signature
		publicKeyBytes := xdr.ScBytes(rawPublicKey)
		signatureBytes := xdr.ScBytes(signature)

		publicKeySymbol := xdr.ScSymbol("public_key")
		signatureSymbol := xdr.ScSymbol("signature")

		scMap := xdr.ScMap{
			xdr.ScMapEntry{
				Key: xdr.ScVal{
					Type: xdr.ScValTypeScvSymbol,
					Sym:  &publicKeySymbol,
				},
				Val: xdr.ScVal{
					Type:  xdr.ScValTypeScvBytes,
					Bytes: &publicKeyBytes,
				},
			},
			xdr.ScMapEntry{
				Key: xdr.ScVal{
					Type: xdr.ScValTypeScvSymbol,
					Sym:  &signatureSymbol,
				},
				Val: xdr.ScVal{
					Type:  xdr.ScValTypeScvBytes,
					Bytes: &signatureBytes,
				},
			},
		}
		scMapPtr := &scMap

		sigEntry := xdr.ScVal{
			Type: xdr.ScValTypeScvMap,
			Map:  &scMapPtr,
		}

		// Set signature as vector with one entry
		vec := xdr.ScVec{sigEntry}
		vecPtr := &vec
		addrCreds.Signature = xdr.ScVal{
			Type: xdr.ScValTypeScvVec,
			Vec:  &vecPtr,
		}
	}

	// Encode entries back to base64 XDR
	// First, write the array length
	resultBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(resultBytes, uint32(len(entries)))

	// Then append each entry
	for i := range entries {
		entryBytes, err := entries[i].MarshalBinary()
		if err != nil {
			return "", fmt.Errorf("failed to marshal entry %d: %w", i, err)
		}
		resultBytes = append(resultBytes, entryBytes...)
	}

	// Encode to base64
	return base64.StdEncoding.EncodeToString(resultBytes), nil
}
