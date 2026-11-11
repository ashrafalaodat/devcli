package api_test

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"devctl.local/devctl/internal/api"
	"devctl.local/devctl/internal/model"
	"github.com/google/uuid"
	"k8s.io/client-go/tools/clientcmd"
)

type patTokenAuth struct{}

func (patTokenAuth) Verify(_ context.Context, raw string) (model.Identity, error) {
	if raw != "alice" && raw != "bob" && raw != "admin" {
		return model.Identity{}, errors.New("invalid")
	}
	return model.Identity{Issuer: "https://issuer.test", Subject: raw, Name: raw, Admin: raw == "admin"}, nil
}

func createPersonal(t *testing.T, g *gatewayTest, token string) api.PATCreation {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"name": "laptop"})
	r := request(t, "POST", g.frontend.URL+"/v1/pats", token, string(body))
	defer r.Body.Close()
	if r.StatusCode != 201 {
		t.Fatal("PAT creation failed", r.StatusCode)
	}
	var result api.PATCreation
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func personalSecret(t *testing.T, p api.PATCreation) string {
	t.Helper()
	cfg, err := clientcmd.Load([]byte(p.Kubeconfig))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AuthInfos) != 1 || cfg.AuthInfos["devctl-personal-access"].Exec != nil {
		t.Fatal("browser config requires installed executable")
	}
	return cfg.AuthInfos["devctl-personal-access"].Token
}

func TestPersonalGatewayConfigAndControlScope(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer upstream-secret-only" {
			http.Error(w, "client credential leaked upstream", 400)
			return
		}
		fmt.Fprint(w, `{"gitVersion":"v1.35.1"}`)
	}), false)
	g.app.Auth = patTokenAuth{}
	p := createPersonal(t, g, "alice")
	secret := personalSecret(t, p)
	if strings.Contains(p.Kubeconfig, "upstream-secret") || strings.Contains(p.Kubeconfig, g.upstream.URL) || strings.Contains(p.Kubeconfig, "PRIVATE KEY") {
		t.Fatal("browser config leaked original credentials")
	}
	for _, test := range []struct {
		path, token string
		code        int
	}{
		{g.url("/version"), secret, 200},
		{g.frontend.URL + "/k8s/sessions/s-" + uuid.NewString() + "/version", secret, 410},
		{g.frontend.URL + "/k8s/auto/a-" + uuid.NewString() + "/version", secret, 410},
		{g.frontend.URL + "/v1/whoami", secret, 401},
		{g.frontend.URL + "/v1/pats", secret, 401},
		{g.frontend.URL + "/v1/admin/audit", secret, 401},
		{g.frontend.URL + "/v1/pats?all=true", "bob", 403},
		{g.frontend.URL + "/v1/admin/audit", "alice", 403},
		{g.frontend.URL + "/v1/admin/audit?limit=501", "admin", 400},
		{g.frontend.URL + "/v1/admin/audit?limit=5", "admin", 200},
	} {
		r := request(t, "GET", test.path, test.token, "")
		body := readResponse(t, r)
		if r.StatusCode != test.code {
			t.Fatal("unexpected scoped response", test.path, r.StatusCode)
		}
		if strings.Contains(body, secret) || strings.Contains(body, "token_digest") {
			t.Fatal("credential material leaked in response")
		}
	}
	r := request(t, "GET", g.frontend.URL+"/v1/pats", "bob", "")
	if body := readResponse(t, r); r.StatusCode != 200 || strings.TrimSpace(body) != "[]" {
		t.Fatal("foreign metadata leaked")
	}
	r = request(t, "GET", g.frontend.URL+"/v1/pats?all=true", "admin", "")
	var all []any
	if err := json.Unmarshal([]byte(readResponse(t, r)), &all); err != nil || len(all) != 1 {
		t.Fatal("admin PAT listing failed", err)
	}
	r = request(t, "POST", g.frontend.URL+"/v1/pats", "bob", fmt.Sprintf(`{"session_id":%q,"name":"foreign"}`, g.session.ID))
	readResponse(t, r)
	if r.StatusCode != 400 {
		t.Fatal("legacy session-scoped PAT creation accepted")
	}
	r = request(t, "DELETE", g.frontend.URL+"/v1/pats/"+p.PAT.ID, "bob", "")
	readResponse(t, r)
	if r.StatusCode != 403 {
		t.Fatal("foreign PAT revocation allowed")
	}
	r = request(t, "DELETE", g.frontend.URL+"/v1/pats/"+p.PAT.ID, "admin", "")
	readResponse(t, r)
	if r.StatusCode != 409 {
		t.Fatal("admin revocation omitted audit reason")
	}
	r = request(t, "DELETE", g.frontend.URL+"/v1/pats/"+p.PAT.ID, "admin", `{"reason":"lost laptop"}`)
	readResponse(t, r)
	if r.StatusCode != 200 {
		t.Fatal("admin PAT revocation failed")
	}
	r = request(t, "GET", g.url("/version"), secret, "")
	readResponse(t, r)
	if r.StatusCode != 401 {
		t.Fatal("revoked PAT accepted")
	}
}

func TestPersonalConfigWorksWithStockKubectl(t *testing.T) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("kubectl not installed")
	}
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer upstream-secret-only" {
			http.Error(w, "wrong authentication", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"major":"1","minor":"35","gitVersion":"v1.35.1"}`)
	}), false)
	tlsFront := httptest.NewTLSServer(g.app.Handler())
	defer tlsFront.Close()
	g.app.PublicURL = tlsFront.URL
	g.app.GatewayCAData = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsFront.Certificate().Raw})
	p := createPersonal(t, g, "alice")
	secret := personalSecret(t, p)
	file := filepath.Join(t.TempDir(), "gateway-config")
	if err = os.WriteFile(file, []byte(p.Kubeconfig), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(kubectl, "--cache-dir", t.TempDir(), "--kubeconfig", file, "get", "--raw=/version", "--request-timeout=5s")
	// No devctl binary or plugin on PATH: only stock kubectl and this YAML.
	command.Env = []string{"PATH=" + t.TempDir()}
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "v1.35.1") {
		t.Fatal("stock kubectl gateway request failed", err, string(output))
	}
	if strings.Contains(string(output), secret) {
		t.Fatal("kubectl exposed credential")
	}
	if err = g.db.RevokePAT(context.Background(), g.alice, p.PAT.ID, ""); err != nil {
		t.Fatal(err)
	}
	command = exec.Command(kubectl, "--cache-dir", t.TempDir(), "--kubeconfig", file, "get", "--raw=/version", "--request-timeout=5s")
	command.Env = []string{"PATH=" + t.TempDir()}
	if err = command.Run(); err == nil {
		t.Fatal("stock kubectl retained access after PAT revocation")
	}
}

func TestPersonalGatewayStreamRevocation(t *testing.T) {
	for _, end := range []string{"revoke", "expiry", "session-stop", "logout", "db-unavailable"} {
		t.Run(end, func(t *testing.T) {
			g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, `{"type":"ADDED"}`)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}), false)
			p := createPersonal(t, g, "alice")
			secret := personalSecret(t, p)
			r := request(t, "GET", g.url("/api/v1/pods?watch=true"), secret, "")
			defer r.Body.Close()
			reader := bufio.NewReader(r.Body)
			if _, err := reader.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
			var err error
			switch end {
			case "revoke":
				err = g.db.RevokePAT(context.Background(), g.alice, p.PAT.ID, "")
			case "expiry":
				_, err = g.db.Pool.Exec(context.Background(), "UPDATE personal_access_tokens SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1", p.PAT.ID)
			case "session-stop":
				err = g.db.Stop(context.Background(), g.alice, g.session.ID, "test", false)
			case "logout":
				err = g.db.Logout(context.Background(), g.alice)
			case "db-unavailable":
				g.db.Pool.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := reader.ReadByte(); done <- err }()
			select {
			case err = <-done:
				if err == nil {
					t.Fatal("stream still authorized")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("PAT stream did not close")
			}
		})
	}
}

func TestPersonalGatewayDuplexRevocation(t *testing.T) {
	upDone := make(chan struct{})
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		defer close(upDone)
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		rw.Flush()
		io.Copy(conn, rw)
	}), false)
	p := createPersonal(t, g, "alice")
	secret := personalSecret(t, p)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(g.frontend.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	req, _ := http.NewRequest("POST", g.url("/api/v1/namespaces/default/pods/p/exec"), nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if err = req.Write(conn); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, req)
	if err != nil || response.StatusCode != 101 {
		t.Fatal("upgrade failed", err)
	}
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if _, err = io.ReadFull(reader, buffer); err != nil || string(buffer) != "ping" {
		t.Fatal("duplex connection failed", err)
	}
	if err = g.db.RevokePAT(context.Background(), g.alice, p.PAT.ID, ""); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = reader.ReadByte(); err == nil {
		t.Fatal("revoked duplex connection remained open")
	}
	select {
	case <-upDone:
	case <-time.After(time.Second):
		t.Fatal("upstream connection retained")
	}
}
