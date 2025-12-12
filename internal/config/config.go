package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds the server configuration
type Config struct {
	// Server configuration
	Host string `json:"host"`
	Port int    `json:"port"`

	// Stellar keypair configuration
	AccountID string `json:"account_id"`
	Secret    string `json:"secret"`

	// Network configuration
	NetworkPassphrase string `json:"network_passphrase"`
	SorobanRPCURL     string `json:"soroban_rpc_url"`

	// Authentication
	BearerToken string `json:"bearer_token"`
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(file, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate required fields
	if cfg.AccountID == "" {
		return nil, fmt.Errorf("account_id is required")
	}
	if cfg.Secret == "" {
		return nil, fmt.Errorf("secret is required")
	}
	if cfg.BearerToken == "" {
		return nil, fmt.Errorf("bearer_token is required")
	}

	// Set defaults
	if cfg.Host == "" {
		cfg.Host = "0.0.0.0"
	}
	if cfg.Port == 0 {
		cfg.Port = 5003
	}
	if cfg.NetworkPassphrase == "" {
		cfg.NetworkPassphrase = "Test SDF Network ; September 2015"
	}
	if cfg.SorobanRPCURL == "" {
		cfg.SorobanRPCURL = "https://soroban-testnet.stellar.org"
	}

	return &cfg, nil
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() (*Config, error) {
	cfg := &Config{
		Host:              getEnv("HOST", "0.0.0.0"),
		Port:              getEnvInt("PORT", 5003),
		AccountID:         getEnv("ACCOUNT_ID", ""),
		Secret:            getEnv("SECRET", ""),
		NetworkPassphrase: getEnv("NETWORK_PASSPHRASE", "Test SDF Network ; September 2015"),
		SorobanRPCURL:     getEnv("SOROBAN_RPC_URL", "https://soroban-testnet.stellar.org"),
		BearerToken:       getEnv("BEARER_TOKEN", "987654321"),
	}

	// Validate required fields
	if cfg.AccountID == "" {
		return nil, fmt.Errorf("ACCOUNT_ID environment variable is required")
	}
	if cfg.Secret == "" {
		return nil, fmt.Errorf("SECRET environment variable is required")
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intValue int
		if _, err := fmt.Sscanf(value, "%d", &intValue); err == nil {
			return intValue
		}
	}
	return defaultValue
}
