package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
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

type autoBookingInput struct {
	Enabled  *bool             `json:"enabled"`
	Selector map[string]string `json:"selector"`
}

func (b *autoBookingInput) policy() (model.AutoBookingPolicy, error) {
	if b == nil {
		return model.AutoBookingPolicy{Selector: map[string]string{}}, nil
	}
	if b.Enabled == nil {
		return model.AutoBookingPolicy{}, fmt.Errorf("auto_booking.enabled boolean is required")
	}
	policy := model.AutoBookingPolicy{Enabled: *b.Enabled, Selector: b.Selector}
	if policy.Selector == nil {
		policy.Selector = map[string]string{}
	}
	return policy, model.ValidateAutoBookingPolicy(policy)
}

func (s *Server) createPAT(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name        string            `json:"name"`
		TTL         string            `json:"ttl"`
		AutoBooking *autoBookingInput `json:"auto_booking"`
	}
	if err := decode(w, r, &b); err != nil || strings.TrimSpace(b.Name) == "" || len(b.Name) > 100 {
		fail(w, http.StatusBadRequest, "credential name (1 through 100 bytes) required; PATs follow your primary cluster")
		return
	}
	policy, err := b.AutoBooking.policy()
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
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
	metadata, secret, err := s.Store.CreatePATWithPolicy(r.Context(), user(r), b.Name, ttl, policy)
	if err != nil {
		respond(w, err, nil)
		return
	}
	cfg := clientapi.NewConfig()
	cfg.CurrentContext = "devctl"
	cfg.Clusters["devctl-gateway"] = &clientapi.Cluster{Server: strings.TrimSuffix(s.PublicURL, "/") + "/k8s", CertificateAuthorityData: ca}
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

func (s *Server) getPAT(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.PAT(r.Context(), user(r), r.PathValue("id"))
	respond(w, err, v)
}

func (s *Server) updatePAT(w http.ResponseWriter, r *http.Request) {
	var b struct {
		AutoBooking *autoBookingInput `json:"auto_booking"`
		Reason      string            `json:"reason"`
	}
	if err := decode(w, r, &b); err != nil || b.AutoBooking == nil || len(b.Reason) > 1000 {
		fail(w, http.StatusBadRequest, "auto_booking with enabled boolean and selector is required; audit reason must be at most 1000 bytes")
		return
	}
	policy, err := b.AutoBooking.policy()
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	v, err := s.Store.UpdatePATBooking(r.Context(), user(r), r.PathValue("id"), policy, b.Reason)
	respond(w, err, v)
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
