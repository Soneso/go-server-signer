package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/cors"
	"github.com/Soneso/go-server-signer/internal/config"
	"github.com/Soneso/go-server-signer/internal/handler"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "", "Path to config JSON file (optional, uses env vars if not provided)")
	flag.Parse()

	// Load configuration
	var cfg *config.Config
	var err error

	if *configPath != "" {
		cfg, err = config.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config from file: %v", err)
		}
		log.Printf("Loaded configuration from file: %s", *configPath)
	} else {
		cfg, err = config.LoadFromEnv()
		if err != nil {
			log.Fatalf("Failed to load config from environment: %v", err)
		}
		log.Println("Loaded configuration from environment variables")
	}

	// Create handler
	h := handler.New(cfg)

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/sign-sep-10", h.Sign)
	mux.HandleFunc("/sign-sep-45", h.Sign45)
	mux.HandleFunc("/.well-known/stellar.toml", h.StellarToml)
	mux.HandleFunc("/health", h.Health)

	// Setup CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	// Create server
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      corsHandler.Handler(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting server on %s", addr)
		log.Printf("Account ID: %s", cfg.AccountID)
		log.Printf("Network Passphrase: %s", cfg.NetworkPassphrase)
		log.Println("Endpoints:")
		log.Println("  POST   /sign-sep-10")
		log.Println("  POST   /sign-sep-45")
		log.Println("  GET    /.well-known/stellar.toml")
		log.Println("  GET    /health")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}
