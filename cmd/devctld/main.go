package main

import (
	"context"
	"devctl.local/devctl/internal/api"
	"devctl.local/devctl/internal/auth"
	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/store"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func main() {
	if e := run(); e != nil {
		slog.Error("backend stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	issuer := env("DEVCTL_ISSUER", "http://127.0.0.1:8081/realms/devctl")
	cfg := auth.DefaultConfig(issuer)
	if raw := os.Getenv("DEVCTL_OIDC_CONFIG"); raw != "" {
		if e := json.Unmarshal([]byte(raw), &cfg); e != nil {
			return e
		}
	}
	if !strings.HasPrefix(cfg.Issuer, "https://") && os.Getenv("DEVCTL_DEV_HTTP") != "1" {
		return errors.New("OIDC requires HTTPS; DEVCTL_DEV_HTTP=1 allows local development only")
	}
	startup, startupCancel := context.WithTimeout(ctx, 30*time.Second)
	defer startupCancel()
	verifier, e := auth.New(startup, cfg)
	if e != nil {
		return e
	}
	key, e := base64.StdEncoding.DecodeString(os.Getenv("DEVCTL_MASTER_KEY"))
	if e != nil {
		return errors.New("invalid base64 master key")
	}
	vault, e := kube.NewVault(key)
	if e != nil {
		return e
	}
	if os.Getenv("DATABASE_URL") == "" {
		return errors.New("DATABASE_URL is required")
	}
	db, e := store.Open(startup, os.Getenv("DATABASE_URL"))
	if e != nil {
		return e
	}
	defer db.Pool.Close()
	addr := env("DEVCTL_LISTEN", "127.0.0.1:9090")
	host, _, e := net.SplitHostPort(addr)
	if e != nil {
		return e
	}
	ip := net.ParseIP(host)
	if (ip == nil || !ip.IsLoopback()) && os.Getenv("DEVCTL_TLS_CERT") == "" {
		return errors.New("non-loopback listener requires DEVCTL_TLS_CERT and DEVCTL_TLS_KEY")
	}
	publicURL := os.Getenv("DEVCTL_PUBLIC_URL")
	if publicURL == "" && ip != nil && ip.IsLoopback() {
		scheme := "http"
		if os.Getenv("DEVCTL_TLS_CERT") != "" {
			scheme = "https"
		}
		publicURL = scheme + "://" + addr
	}
	if e = api.ValidatePublicURL(publicURL); e != nil {
		return e
	}
	var gatewayCA []byte
	if file := os.Getenv("DEVCTL_GATEWAY_CA_FILE"); file != "" {
		rawCA, readErr := os.ReadFile(file)
		if readErr != nil {
			return errors.New("cannot read gateway CA file")
		}
		gatewayCA, e = kube.PublicCertificates(rawCA)
		if e != nil {
			return e
		}
	}
	recheck, e := time.ParseDuration(env("DEVCTL_GATEWAY_RECHECK_INTERVAL", "1s"))
	if e != nil || recheck < 100*time.Millisecond || recheck > 30*time.Second {
		return errors.New("gateway recheck interval must be 100ms through 30s")
	}
	srv := &http.Server{Addr: addr, Handler: (&api.Server{Store: db, Auth: verifier, Vault: vault, PublicURL: publicURL, GatewayCAData: gatewayCA, GatewayRecheckInterval: recheck}).Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				task, done := context.WithTimeout(ctx, 10*time.Second)
				if e := db.Expire(task); e != nil {
					slog.Error("reservation expiry failed")
				}
				done()
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		srv.Shutdown(shutdown)
	}()
	slog.Info("devctld listening", "address", addr, "mode", "authenticated Kubernetes gateway; upstream credentials remain on server")
	if cert := os.Getenv("DEVCTL_TLS_CERT"); cert != "" {
		e = srv.ListenAndServeTLS(cert, os.Getenv("DEVCTL_TLS_KEY"))
	} else {
		e = srv.ListenAndServe()
	}
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
