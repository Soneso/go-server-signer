package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Soneso/go-server-signer/internal/config"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/network"
	"github.com/stellar/go/txnbuild"
)

func TestSign_Success(t *testing.T) {
	// Create test configuration
	kp, err := keypair.Random()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	cfg := &config.Config{
		AccountID:         kp.Address(),
		Secret:            kp.Seed(),
		BearerToken:       "test-token",
		NetworkPassphrase: network.TestNetworkPassphrase,
	}

	h := New(cfg)

	// Create a test transaction
	sourceAccount := txnbuild.NewSimpleAccount(kp.Address(), 0)
	tx, err := txnbuild.NewTransaction(
		txnbuild.TransactionParams{
			SourceAccount:        &sourceAccount,
			IncrementSequenceNum: true,
			Operations: []txnbuild.Operation{
				&txnbuild.ManageData{
					Name:  "test",
					Value: []byte("test data"),
				},
			},
			BaseFee:       txnbuild.MinBaseFee,
			Preconditions: txnbuild.Preconditions{TimeBounds: txnbuild.NewTimeout(300)},
		},
	)
	if err != nil {
		t.Fatalf("failed to build transaction: %v", err)
	}

	txXDR, err := tx.Base64()
	if err != nil {
		t.Fatalf("failed to encode transaction: %v", err)
	}

	// Create request
	reqBody := SignRequest{
		Transaction:       txXDR,
		NetworkPassphrase: network.TestNetworkPassphrase,
	}
	reqBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sign-sep-10", bytes.NewReader(reqBytes))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	h.Sign(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp SignResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Transaction == "" {
		t.Error("expected signed transaction in response")
	}
	if resp.NetworkPassphrase != network.TestNetworkPassphrase {
		t.Error("network passphrase mismatch")
	}
}

func TestSign_MissingAuth(t *testing.T) {
	cfg := &config.Config{
		BearerToken: "test-token",
	}
	h := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/sign-sep-10", nil)
	rr := httptest.NewRecorder()
	h.Sign(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rr.Code)
	}
}

func TestSign_InvalidToken(t *testing.T) {
	cfg := &config.Config{
		BearerToken: "test-token",
	}
	h := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/sign-sep-10", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	h.Sign(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rr.Code)
	}
}

func TestSign_MissingTransaction(t *testing.T) {
	cfg := &config.Config{
		BearerToken: "test-token",
	}
	h := New(cfg)

	reqBody := SignRequest{
		NetworkPassphrase: network.TestNetworkPassphrase,
	}
	reqBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sign-sep-10", bytes.NewReader(reqBytes))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	h.Sign(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}
}

func TestSign_MissingNetworkPassphrase(t *testing.T) {
	cfg := &config.Config{
		BearerToken: "test-token",
	}
	h := New(cfg)

	reqBody := SignRequest{
		Transaction: "test-xdr",
	}
	reqBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sign-sep-10", bytes.NewReader(reqBytes))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	h.Sign(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}
}

func TestStellarToml_Success(t *testing.T) {
	cfg := &config.Config{
		AccountID:         "GBUTDNISXHXBMZE5I4U5INJTY376S5EW2AF4SQA2SWBXUXJY3OIZQHMV",
		NetworkPassphrase: network.TestNetworkPassphrase,
	}
	h := New(cfg)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/stellar.toml", nil)
	rr := httptest.NewRecorder()
	h.StellarToml(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if body == "" {
		t.Error("expected non-empty response body")
	}

	// Check that the response contains the account ID
	if !bytes.Contains([]byte(body), []byte(cfg.AccountID)) {
		t.Error("response should contain account ID")
	}
}

func TestHealth_Success(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	h.Health(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["status"] != "ok" {
		t.Error("expected status: ok")
	}
}

func TestSign_MethodNotAllowed(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg)

	req := httptest.NewRequest(http.MethodGet, "/sign-sep-10", nil)
	rr := httptest.NewRecorder()
	h.Sign(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rr.Code)
	}
}

func TestSign45_MethodNotAllowed(t *testing.T) {
	cfg := &config.Config{}
	h := New(cfg)

	req := httptest.NewRequest(http.MethodGet, "/sign-sep-45", nil)
	rr := httptest.NewRecorder()
	h.Sign45(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rr.Code)
	}
}
