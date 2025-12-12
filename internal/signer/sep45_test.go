package signer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stellar/go/keypair"
	"github.com/stellar/go/network"
	"github.com/stellar/go/strkey"
	"github.com/stellar/go/xdr"
)

func TestSignSEP45AuthorizationEntries(t *testing.T) {
	// Test keypair and account
	secretKey := "SBRSOOURG2E24VGDR6NKZJMBOSOHVT6GV7EECUR3ZBE7LGSSVYN5VMOG"
	expectedAccount := "GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV"
	networkPassphrase := network.TestNetworkPassphrase

	// Parse keypair to get public key bytes
	kp, err := keypair.Parse(secretKey)
	if err != nil {
		t.Fatalf("failed to parse test keypair: %v", err)
	}

	// Verify account ID matches expected
	if kp.Address() != expectedAccount {
		t.Fatalf("account mismatch: expected %s, got %s", expectedAccount, kp.Address())
	}

	// Get raw public key bytes
	rawPublicKey, err := strkey.Decode(strkey.VersionByteAccountID, expectedAccount)
	if err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}

	// Create a mock Soroban RPC server
	mockLedgerSeq := uint32(1000)
	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode RPC request: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if req.Method != "getLatestLedger" {
			t.Errorf("unexpected RPC method: %s", req.Method)
			http.Error(w, "invalid method", http.StatusBadRequest)
			return
		}

		resp := rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
		}
		resp.Result.Sequence = mockLedgerSeq

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("failed to encode RPC response: %v", err)
		}
	}))
	defer rpcServer.Close()

	// Build test authorization entry
	entry := createTestAuthorizationEntry(t, expectedAccount)

	// Encode entry to XDR array format (4 bytes length + XDR data)
	entriesXDR := encodeAuthorizationEntries(t, []xdr.SorobanAuthorizationEntry{entry})

	// Sign the authorization entries
	signedEntriesXDR, err := SignSEP45AuthorizationEntries(entriesXDR, networkPassphrase, secretKey, rpcServer.URL)
	if err != nil {
		t.Fatalf("SignSEP45AuthorizationEntries failed: %v", err)
	}

	// Decode the signed entries
	signedEntries := decodeAuthorizationEntries(t, signedEntriesXDR)
	if len(signedEntries) != 1 {
		t.Fatalf("expected 1 signed entry, got %d", len(signedEntries))
	}

	signedEntry := signedEntries[0]

	// Verify credentials type
	if signedEntry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddress {
		t.Fatalf("unexpected credentials type: %v", signedEntry.Credentials.Type)
	}

	addrCreds := signedEntry.Credentials.Address
	if addrCreds == nil {
		t.Fatal("address credentials are nil")
	}

	// Verify signature expiration ledger was set
	if addrCreds.SignatureExpirationLedger == 0 {
		t.Fatal("signatureExpirationLedger was not set")
	}
	expectedExpiration := xdr.Uint32(mockLedgerSeq + 10)
	if addrCreds.SignatureExpirationLedger != expectedExpiration {
		t.Errorf("expected signatureExpirationLedger %d, got %d", expectedExpiration, addrCreds.SignatureExpirationLedger)
	}

	// Verify signature is set and is a vector
	if addrCreds.Signature.Type != xdr.ScValTypeScvVec {
		t.Fatalf("signature is not a vector: %v", addrCreds.Signature.Type)
	}

	sigVec := addrCreds.Signature.Vec
	if sigVec == nil || len(**sigVec) != 1 {
		t.Fatal("signature vector should contain exactly one entry")
	}

	// Verify signature entry is a map
	sigEntry := (**sigVec)[0]
	if sigEntry.Type != xdr.ScValTypeScvMap {
		t.Fatalf("signature entry is not a map: %v", sigEntry.Type)
	}

	sigMap := *sigEntry.Map
	if len(*sigMap) != 2 {
		t.Fatalf("signature map should have 2 entries, got %d", len(*sigMap))
	}

	// Extract public_key and signature from map
	var foundPublicKey, foundSignature []byte
	for _, mapEntry := range *sigMap {
		if mapEntry.Key.Type != xdr.ScValTypeScvSymbol {
			t.Errorf("map key is not a symbol: %v", mapEntry.Key.Type)
			continue
		}

		key := string(*mapEntry.Key.Sym)
		if mapEntry.Val.Type != xdr.ScValTypeScvBytes {
			t.Errorf("map value for %s is not bytes: %v", key, mapEntry.Val.Type)
			continue
		}

		value := []byte(*mapEntry.Val.Bytes)

		switch key {
		case "public_key":
			foundPublicKey = value
		case "signature":
			foundSignature = value
		default:
			t.Errorf("unexpected map key: %s", key)
		}
	}

	// Verify public key
	if foundPublicKey == nil {
		t.Fatal("public_key not found in signature map")
	}
	if !bytes.Equal(foundPublicKey, rawPublicKey) {
		t.Errorf("public key mismatch: expected %x, got %x", rawPublicKey, foundPublicKey)
	}

	// Verify signature
	if foundSignature == nil {
		t.Fatal("signature not found in signature map")
	}
	if len(foundSignature) != ed25519.SignatureSize {
		t.Errorf("signature has wrong length: expected %d, got %d", ed25519.SignatureSize, len(foundSignature))
	}

	// Verify signature is cryptographically valid
	verifySignature(t, signedEntry, networkPassphrase, foundPublicKey, foundSignature)
}

func TestSignSEP45AuthorizationEntries_InvalidBase64(t *testing.T) {
	secretKey := "SBRSOOURG2E24VGDR6NKZJMBOSOHVT6GV7EECUR3ZBE7LGSSVYN5VMOG"
	networkPassphrase := network.TestNetworkPassphrase

	_, err := SignSEP45AuthorizationEntries("invalid-base64!!!", networkPassphrase, secretKey, "http://localhost:8000")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestSignSEP45AuthorizationEntries_InvalidSecret(t *testing.T) {
	entry := createTestAuthorizationEntry(t, "GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV")
	entriesXDR := encodeAuthorizationEntries(t, []xdr.SorobanAuthorizationEntry{entry})

	_, err := SignSEP45AuthorizationEntries(entriesXDR, network.TestNetworkPassphrase, "invalid-secret", "http://localhost:8000")
	if err == nil {
		t.Fatal("expected error for invalid secret key")
	}
}

func TestSignSEP45AuthorizationEntries_EmptyEntries(t *testing.T) {
	secretKey := "SBRSOOURG2E24VGDR6NKZJMBOSOHVT6GV7EECUR3ZBE7LGSSVYN5VMOG"
	networkPassphrase := network.TestNetworkPassphrase

	// Create XDR with zero entries
	xdrBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(xdrBytes, 0)
	entriesXDR := base64.StdEncoding.EncodeToString(xdrBytes)

	_, err := SignSEP45AuthorizationEntries(entriesXDR, networkPassphrase, secretKey, "http://localhost:8000")
	if err == nil {
		t.Fatal("expected error for empty entries")
	}
}

func TestSignSEP45AuthorizationEntries_RPCFailure(t *testing.T) {
	secretKey := "SBRSOOURG2E24VGDR6NKZJMBOSOHVT6GV7EECUR3ZBE7LGSSVYN5VMOG"
	expectedAccount := "GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV"
	networkPassphrase := network.TestNetworkPassphrase

	// Create a mock RPC server that returns an error
	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "RPC error", http.StatusInternalServerError)
	}))
	defer rpcServer.Close()

	entry := createTestAuthorizationEntry(t, expectedAccount)
	entriesXDR := encodeAuthorizationEntries(t, []xdr.SorobanAuthorizationEntry{entry})

	_, err := SignSEP45AuthorizationEntries(entriesXDR, networkPassphrase, secretKey, rpcServer.URL)
	if err == nil {
		t.Fatal("expected error when RPC fails")
	}
}

func TestSignSEP45AuthorizationEntries_MultipleEntries(t *testing.T) {
	secretKey := "SBRSOOURG2E24VGDR6NKZJMBOSOHVT6GV7EECUR3ZBE7LGSSVYN5VMOG"
	expectedAccount := "GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV"
	networkPassphrase := network.TestNetworkPassphrase

	mockLedgerSeq := uint32(2000)
	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		json.NewDecoder(r.Body).Decode(&req)
		resp := rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
		}
		resp.Result.Sequence = mockLedgerSeq
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer rpcServer.Close()

	// Create a second keypair for another account
	otherKp, err := keypair.Random()
	if err != nil {
		t.Fatalf("failed to generate random keypair: %v", err)
	}

	// Create multiple entries - one for our account, one for another account
	entry1 := createTestAuthorizationEntry(t, expectedAccount)
	entry2 := createTestAuthorizationEntry(t, otherKp.Address())

	entriesXDR := encodeAuthorizationEntries(t, []xdr.SorobanAuthorizationEntry{entry1, entry2})

	signedEntriesXDR, err := SignSEP45AuthorizationEntries(entriesXDR, networkPassphrase, secretKey, rpcServer.URL)
	if err != nil {
		t.Fatalf("SignSEP45AuthorizationEntries failed: %v", err)
	}

	signedEntries := decodeAuthorizationEntries(t, signedEntriesXDR)
	if len(signedEntries) != 2 {
		t.Fatalf("expected 2 signed entries, got %d", len(signedEntries))
	}

	// First entry should be signed
	if signedEntries[0].Credentials.Address.Signature.Type != xdr.ScValTypeScvVec {
		t.Error("first entry should be signed")
	}

	// Second entry should NOT be signed (different account)
	if signedEntries[1].Credentials.Address.SignatureExpirationLedger != 0 {
		t.Error("second entry should not have expiration set")
	}
}

// Helper functions

func createTestAuthorizationEntry(t *testing.T, accountID string) xdr.SorobanAuthorizationEntry {
	t.Helper()

	// Create account ID using helper
	accountIDXDR := xdr.MustAddress(accountID)

	// Create address
	address := xdr.ScAddress{
		Type:      xdr.ScAddressTypeScAddressTypeAccount,
		AccountId: &accountIDXDR,
	}

	// Create a simple root invocation (mock contract call)
	contractIDBytes := [32]byte{}
	copy(contractIDBytes[:], []byte("test_contract"))
	contractID := xdr.ContractId(contractIDBytes)
	contractAddress := xdr.ScAddress{
		Type:       xdr.ScAddressTypeScAddressTypeContract,
		ContractId: &contractID,
	}

	functionName := xdr.ScSymbol("test_function")
	rootInvocation := xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: contractAddress,
				FunctionName:    functionName,
				Args:            xdr.ScVec{},
			},
		},
		SubInvocations: []xdr.SorobanAuthorizedInvocation{},
	}

	// Create nonce
	nonceBytes := [32]byte{}
	copy(nonceBytes[:], []byte("test_nonce"))
	nonce := xdr.Int64(12345)

	// Create address credentials with signatureExpirationLedger = 0
	addressCreds := xdr.SorobanAddressCredentials{
		Address:                    address,
		Nonce:                      nonce,
		SignatureExpirationLedger:  0, // Should be set by signing function
		Signature:                  xdr.ScVal{Type: xdr.ScValTypeScvVoid},
	}

	// Create authorization entry
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type:    xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			Address: &addressCreds,
		},
		RootInvocation: rootInvocation,
	}

	return entry
}

func encodeAuthorizationEntries(t *testing.T, entries []xdr.SorobanAuthorizationEntry) string {
	t.Helper()

	// Write array length (4 bytes, big-endian)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(entries)))

	// Append each entry
	for i, entry := range entries {
		entryBytes, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("failed to marshal entry %d: %v", i, err)
		}
		buf = append(buf, entryBytes...)
	}

	return base64.StdEncoding.EncodeToString(buf)
}

func decodeAuthorizationEntries(t *testing.T, entriesXDR string) []xdr.SorobanAuthorizationEntry {
	t.Helper()

	xdrBytes, err := base64.StdEncoding.DecodeString(entriesXDR)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}

	if len(xdrBytes) < 4 {
		t.Fatal("XDR too short")
	}

	count := binary.BigEndian.Uint32(xdrBytes[:4])
	entries := make([]xdr.SorobanAuthorizationEntry, 0, count)

	reader := bytes.NewReader(xdrBytes[4:])
	for i := uint32(0); i < count; i++ {
		var entry xdr.SorobanAuthorizationEntry
		_, err := xdr.Unmarshal(reader, &entry)
		if err != nil {
			t.Fatalf("failed to unmarshal entry %d: %v", i, err)
		}
		entries = append(entries, entry)
	}

	return entries
}

func verifySignature(t *testing.T, entry xdr.SorobanAuthorizationEntry, networkPassphrase string, publicKey, signature []byte) {
	t.Helper()

	// Rebuild the preimage
	networkIDBytes := sha256.Sum256([]byte(networkPassphrase))
	var networkID xdr.Hash
	copy(networkID[:], networkIDBytes[:])

	addrCreds := entry.Credentials.Address
	preimage := xdr.HashIdPreimage{
		Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
			NetworkId:                 networkID,
			Nonce:                     addrCreds.Nonce,
			SignatureExpirationLedger: addrCreds.SignatureExpirationLedger,
			Invocation:                entry.RootInvocation,
		},
	}

	preimageBytes, err := preimage.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal preimage: %v", err)
	}

	payload := sha256.Sum256(preimageBytes)

	// Verify the signature using Ed25519
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(publicKey))
	}
	if len(signature) != ed25519.SignatureSize {
		t.Fatalf("invalid signature size: expected %d, got %d", ed25519.SignatureSize, len(signature))
	}

	pubKey := ed25519.PublicKey(publicKey)
	if !ed25519.Verify(pubKey, payload[:], signature) {
		t.Fatal("signature verification failed")
	}
}
