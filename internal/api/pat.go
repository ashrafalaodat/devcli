package api

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/store"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

// PATCreation contains the credential exactly once, inside the generated
// gateway-only kubeconfig. Metadata has no secret or digest fields.
type PATCreation struct {
	PAT        store.PAT `json:"pat"`
	Kubeconfig string    `json:"kubeconfig"`
}

func (s *Server) createPAT(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
		Name      string `json:"name"`
		TTL       string `json:"ttl"`
	}
	if err := decode(w, r, &b); err != nil || !gatewaySessionID.MatchString(b.SessionID) || strings.TrimSpace(b.Name) == "" || len(b.Name) > 100 {
		fail(w, http.StatusBadRequest, "session_id and credential name (1 through 100 bytes) required")
		return
	}
	ttl := store.DefaultPATDuration
	if b.TTL != "" {
		var err error
		ttl, err = time.ParseDuration(b.TTL)
		if err != nil || ttl < time.Minute || ttl > store.MaximumPATDuration {
			fail(w, http.StatusBadRequest, "credential TTL must be 1m through 168h; default 8h")
			return
		}
	}
	if ValidatePublicURL(s.PublicURL) != nil {
		fail(w, http.StatusServiceUnavailable, "gateway public URL is not configured")
		return
	}
	ca := s.GatewayCAData
	if len(ca) > 0 {
		var err error
		ca, err = kube.PublicCertificates(ca)
		if err != nil {
			fail(w, http.StatusServiceUnavailable, "gateway public CA is invalid")
			return
		}
	}
	metadata, secret, err := s.Store.CreatePAT(r.Context(), user(r), b.SessionID, b.Name, ttl)
	if err != nil {
		respond(w, err, nil)
		return
	}
	cfg := clientapi.NewConfig()
	cfg.CurrentContext = "devctl"
	cfg.Clusters["devctl-gateway"] = &clientapi.Cluster{Server: strings.TrimSuffix(s.PublicURL, "/") + "/k8s/sessions/" + url.PathEscape(b.SessionID), CertificateAuthorityData: ca}
	cfg.AuthInfos["devctl-personal-access"] = &clientapi.AuthInfo{Token: secret}
	cfg.Contexts["devctl"] = &clientapi.Context{Cluster: "devctl-gateway", AuthInfo: "devctl-personal-access"}
	raw, err := clientcmd.Write(*cfg)
	if err != nil {
		_ = s.Store.RevokePAT(r.Context(), user(r), metadata.ID, "kubeconfig encoding failed")
		fail(w, http.StatusServiceUnavailable, "gateway configuration unavailable")
		return
	}
	write(w, http.StatusCreated, PATCreation{PAT: metadata, Kubeconfig: string(raw)})
}

func (s *Server) listPATs(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") == "true"
	if v := r.URL.Query().Get("all"); v != "" && v != "true" && v != "false" {
		fail(w, http.StatusBadRequest, "all must be true or false")
		return
	}
	rows, err := s.Store.PATs(r.Context(), user(r), all)
	respond(w, err, rows)
}

func (s *Server) revokePAT(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength != 0 {
		if err := decode(w, r, &b); err != nil {
			fail(w, http.StatusBadRequest, "invalid revocation JSON")
			return
		}
	}
	if len(b.Reason) > 1000 {
		fail(w, http.StatusBadRequest, "audit reason must be at most 1000 bytes")
		return
	}
	err := s.Store.RevokePAT(r.Context(), user(r), r.PathValue("id"), b.Reason)
	respond(w, err, map[string]string{"status": "revoked"})
}

func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 || v > 500 {
			fail(w, http.StatusBadRequest, "limit must be 1 through 500")
			return
		}
		limit = v
	}
	rows, err := s.Store.AuditEvents(r.Context(), user(r), limit)
	respond(w, err, rows)
}
