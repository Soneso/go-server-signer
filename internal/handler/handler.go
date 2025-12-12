package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Soneso/go-server-signer/internal/config"
	"github.com/Soneso/go-server-signer/internal/signer"
)

// Handler holds the HTTP handlers for the server
type Handler struct {
	cfg *config.Config
}

// New creates a new Handler instance
func New(cfg *config.Config) *Handler {
	return &Handler{cfg: cfg}
}

// SignRequest represents the request body for SEP-10 signing
type SignRequest struct {
	Transaction       string `json:"transaction"`
	NetworkPassphrase string `json:"network_passphrase"`
}

// SignResponse represents the response body for SEP-10 signing
type SignResponse struct {
	Transaction       string `json:"transaction"`
	NetworkPassphrase string `json:"network_passphrase"`
}

// Sign45Request represents the request body for SEP-45 signing
type Sign45Request struct {
	AuthorizationEntries string `json:"authorization_entries"`
	NetworkPassphrase    string `json:"network_passphrase"`
}

// Sign45Response represents the response body for SEP-45 signing
type Sign45Response struct {
	AuthorizationEntries string `json:"authorization_entries"`
	NetworkPassphrase    string `json:"network_passphrase"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// authenticate checks the Authorization header for the bearer token
func (h *Handler) authenticate(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return fmt.Errorf("invalid Authorization header format")
	}

	if parts[1] != h.cfg.BearerToken {
		return fmt.Errorf("invalid bearer token")
	}

	return nil
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response
func writeError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, ErrorResponse{Error: message})
}

// Sign handles POST /sign for SEP-10 transaction signing
func (h *Handler) Sign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Authenticate request
	if err := h.authenticate(r); err != nil {
		writeError(w, http.StatusUnauthorized, "Unauthenticated")
		return
	}

	// Parse request body
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate required fields
	if req.Transaction == "" {
		writeError(w, http.StatusBadRequest, "missing transaction parameter")
		return
	}
	if req.NetworkPassphrase == "" {
		writeError(w, http.StatusBadRequest, "missing network_passphrase parameter")
		return
	}

	// Sign the transaction
	signedXDR, err := signer.SignSEP10Transaction(
		req.Transaction,
		req.NetworkPassphrase,
		h.cfg.Secret,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Return signed transaction
	writeJSON(w, http.StatusOK, SignResponse{
		Transaction:       signedXDR,
		NetworkPassphrase: req.NetworkPassphrase,
	})
}

// Sign45 handles POST /sign45 for SEP-45 authorization entries signing
func (h *Handler) Sign45(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Authenticate request
	if err := h.authenticate(r); err != nil {
		writeError(w, http.StatusUnauthorized, "Unauthenticated")
		return
	}

	// Parse request body
	var req Sign45Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate required fields
	if req.AuthorizationEntries == "" {
		writeError(w, http.StatusBadRequest, "missing authorization_entries parameter")
		return
	}
	if req.NetworkPassphrase == "" {
		writeError(w, http.StatusBadRequest, "missing network_passphrase parameter")
		return
	}

	// Sign the authorization entries
	signedEntries, err := signer.SignSEP45AuthorizationEntries(
		req.AuthorizationEntries,
		req.NetworkPassphrase,
		h.cfg.Secret,
		h.cfg.SorobanRPCURL,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Return signed entries
	writeJSON(w, http.StatusOK, Sign45Response{
		AuthorizationEntries: signedEntries,
		NetworkPassphrase:    req.NetworkPassphrase,
	})
}

// StellarToml handles GET /.well-known/stellar.toml
func (h *Handler) StellarToml(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	tomlContent := fmt.Sprintf(`ACCOUNTS = ["%s"]
SIGNING_KEY = "%s"
NETWORK_PASSPHRASE = "%s"
`, h.cfg.AccountID, h.cfg.AccountID, h.cfg.NetworkPassphrase)

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tomlContent))
}

// Health handles GET /health for health checks
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}
