// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	transport "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
}

// Command line flags
var (
	configPath = flag.String("config", "config.yaml", "Path to configuration file")
	debug      = flag.Bool("debug", false, "Enable debug logging")
	initOnly   = flag.Bool("init-only", false, "Initialize database only, then exit")

	// Token management
	listTokens    = flag.Bool("list-tokens", false, "List all auth tokens and exit")
	addToken      = flag.String("add-token", "", "Add auth token: '<token> [description] [expires_hours]'")
	deleteToken   = flag.String("delete-token", "", "Delete auth token and exit")
	cleanupTokens = flag.Bool("cleanup-expired-tokens", false, "Remove expired tokens and exit")

	// Key enrollment
	enrollKey = flag.String("enroll-key", "", "Enroll PEM public key file and exit")
	enrollDID = flag.String("enroll-did", "", "Enroll DID:web URI and exit")
	listKeys  = flag.Bool("list-keys", false, "List enrolled keys and exit")
	deleteKey = flag.String("delete-key", "", "Delete enrolled key by ID or fingerprint and exit")

	// Blob management
	listBlobs           = flag.Bool("list-blobs", false, "List blob audit entries and exit")
	listBlobsByUploader = flag.String("list-blobs-by-uploader", "", "List blobs by uploader ID and exit")
	purgeExpired        = flag.Bool("purge-expired", false, "Purge expired blobs and exit")
	purgeInactive       = flag.Int("purge-inactive", 0, "Purge blobs inactive for N hours and exit")
	purgeByUploader     = flag.String("purge-by-uploader", "", "Purge blobs by uploader ID and exit")
)

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Configure logging
	if *debug || cfg.Debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	// Open database
	state, err := sqlite.Open(cfg.Database.Path, cfg.Database.Password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer state.Close()

	// Initialize custom tables
	if err := InitCustomTables(state.DB()); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing custom tables: %v\n", err)
		os.Exit(1)
	}

	// Create DID resolver
	didResolver := NewDIDResolver(state.DB(), cfg.DIDRefreshThreshold(), cfg.DID.InsecureHTTP)

	// Handle admin CLI commands (exit after)
	if handled, err := handleTokenManagement(state.DB()); handled {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if handled, err := handleKeyManagement(state.DB(), didResolver); handled {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if handled, err := handleBlobManagement(state.DB()); handled {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *initOnly {
		slog.Info("Database initialized successfully", "path", cfg.Database.Path)
		os.Exit(0)
	}

	// --- Server mode ---

	// Parse replacement policy
	rvPolicy, err := parseReplacementPolicy(cfg.RV.ReplacementPolicy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Create TO0 server
	to0 := &fdo.TO0Server{
		Session:                  state,
		RVBlobs:                  state,
		AcceptVoucherWithInfo:    MakeAcceptVoucherWithInfo(cfg, state.DB()),
		VoucherReplacementPolicy: rvPolicy,
	}

	// Create TO1 server
	to1 := &fdo.TO1Server{
		Session: state,
		RVBlobs: state,
	}

	// Create HTTP handler (TO0 + TO1 only; no DI or TO2)
	handler := &transport.Handler{
		Tokens:       state,
		TO0Responder: to0,
		TO1Responder: to1,
	}

	// Wrap with auth middleware if token mode
	var httpHandler http.Handler = handler
	if cfg.Auth.Mode == "token" {
		httpHandler = TokenAuthMiddleware(state.DB(), handler)
	}

	// Add request logging middleware
	httpHandler = loggingMiddleware(httpHandler)

	// Start background pruning if enabled
	if cfg.Pruning.Enabled {
		go runPruningLoop(cfg, state.DB())
	}

	// Start HTTP server
	startServer(cfg, httpHandler)
}

func parseReplacementPolicy(policy string) (fdo.VoucherReplacementPolicy, error) {
	switch policy {
	case "allow-any":
		return fdo.RVPolicyAllowAny, nil
	case "mfg-consistency":
		return fdo.RVPolicyManufacturerKeyConsistency, nil
	case "first-lock":
		return fdo.RVPolicyFirstRegistrationLock, nil
	case "owner-consistency":
		return fdo.RVPolicyOwnerKeyConsistency, nil
	default:
		return 0, fmt.Errorf("unknown replacement policy: %s", policy)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		slog.Debug("request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		next.ServeHTTP(w, r)
		slog.Debug("response", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func runPruningLoop(cfg *Config, db *sql.DB) {
	ticker := time.NewTicker(cfg.PruningInterval())
	defer ticker.Stop()

	slog.Info("background pruning enabled", "interval", cfg.PruningInterval(), "inactive_hours", cfg.Pruning.InactiveHours)

	for range ticker.C {
		n, err := PurgeExpiredBlobs(db)
		if err != nil {
			slog.Error("pruning error", "error", err)
			continue
		}
		if n > 0 {
			slog.Info("pruned expired blobs", "count", n)
		}
	}
}

func startServer(cfg *Config, handler http.Handler) {
	addr := cfg.Server.Addr
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listening on %s: %v\n", addr, err)
		os.Exit(1)
	}

	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-done
		slog.Info("shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("server shutdown error", "error", err)
		}
	}()

	slog.Info("FDO Rendezvous Server starting",
		"addr", addr,
		"auth_mode", cfg.Auth.Mode,
		"replacement_policy", cfg.RV.ReplacementPolicy,
	)

	if err := srv.Serve(listener); err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
	slog.Info("server stopped")
}
