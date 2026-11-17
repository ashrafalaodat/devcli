package main

import (
	"context"
	"devctl.local/devctl/internal/api"
	"devctl.local/devctl/internal/auth"
	"devctl.local/devctl/internal/browser"
	"devctl.local/devctl/internal/health"
	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/webhook"
	"devctl.local/devctl/internal/webui"
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
	addr := env("DEVCTL_LISTEN", "127.0.0.1:9090")
	frontendDevURL := os.Getenv("DEVCTL_FRONTEND_DEV_URL")
	if e := validateFrontendDevelopmentListener(addr, frontendDevURL); e != nil {
		return e
	}
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
	webhookPolicy, e := configuredWebhookPolicy(addr)
	if e != nil {
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
	webTTL, e := time.ParseDuration(env("DEVCTL_WEB_SESSION_TTL", "8h"))
	if e != nil {
		return errors.New("invalid DEVCTL_WEB_SESSION_TTL")
	}
	core := (&api.Server{Store: db, Auth: verifier, Vault: vault, PublicURL: publicURL, GatewayCAData: gatewayCA, GatewayRecheckInterval: recheck, WebhookPolicy: webhookPolicy}).Handler()
	handler, e := browser.New(browser.Config{PublicURL: publicURL, ClientID: env("DEVCTL_WEB_CLIENT_ID", "devctl-web"), ClientSecret: os.Getenv("DEVCTL_WEB_CLIENT_SECRET"), SessionTTL: webTTL, FrontendDevURL: frontendDevURL}, verifier, db, vault, core)
	if e != nil {
		return e
	}
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	// Monitoring mode is durable and disabled by default. The worker uses only
	// registered server-side credentials, without booking or activity paths.
	healthContext, stopHealth := context.WithCancel(ctx)
	healthDone := make(chan struct{})
	go func() {
		defer close(healthDone)
		if err := health.NewWorker(db, vault).Run(healthContext); err != nil {
			slog.Error("cluster health worker stopped")
		}
	}()
	defer func() {
		stopHealth()
		<-healthDone
	}()
	webhookContext, stopWebhooks := context.WithCancel(ctx)
	webhookDone := make(chan struct{})
	go func() {
		defer close(webhookDone)
		if err := webhook.NewWorker(db, vault, webhookPolicy, publicURL).Run(webhookContext); err != nil {
			slog.Error("webhook worker stopped")
		}
	}()
	defer func() { stopWebhooks(); <-webhookDone }()

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
				if e := db.PruneWebSessions(task); e != nil {
					slog.Error("browser session expiry failed")
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

func configuredWebhookPolicy(address string) (webhook.Policy, error) {
	policy := webhook.Policy{AllowedOrigins: []string{}}
	for _, origin := range strings.Split(os.Getenv("DEVCTL_WEBHOOK_ALLOWED_ORIGINS"), ",") {
		if value := strings.TrimSpace(origin); value != "" {
			policy.AllowedOrigins = append(policy.AllowedOrigins, value)
		}
	}
	if os.Getenv("DEVCTL_DEV_WEBHOOK_LOOPBACK") == "1" {
		host, _, err := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if err != nil || os.Getenv("DEVCTL_DEV_HTTP") != "1" || host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return policy, errors.New("development webhook loopback requires a loopback backend listener and DEVCTL_DEV_HTTP=1")
		}
		policy.AllowLoopback = true
	}
	if path := os.Getenv("DEVCTL_WEBHOOK_CA_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return policy, errors.New("cannot read webhook CA file")
		}
		policy.CAPEM, err = kube.PublicCertificates(raw)
		if err != nil {
			return policy, errors.New("webhook CA file must contain only public certificates")
		}
	}
	for _, origin := range policy.AllowedOrigins {
		if err := policy.Validate(origin); err != nil {
			return policy, errors.New("webhook allowed origins must be approved HTTPS origins without credentials, query or fragment")
		}
	}
	return policy, nil
}

func validateFrontendDevelopmentListener(addr, frontendDevURL string) error {
	if frontendDevURL == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || !webui.IsLoopbackHost(host) {
		return errors.New("DEVCTL_FRONTEND_DEV_URL requires a loopback DEVCTL_LISTEN address")
	}
	if _, err := webui.NewHandler(frontendDevURL); err != nil {
		return err
	}
	return nil
}
