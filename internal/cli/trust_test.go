package cli

import (
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAPITrustUsesExplicitCAAndStillVerifiesTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "trusted") }))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	path := filepath.Join(t.TempDir(), "public-ca.pem")
	if e := os.WriteFile(path, certificate, 0600); e != nil {
		t.Fatal(e)
	}
	client := &Client{HTTP: &http.Client{}}
	if e := client.configureAPITrust(path); e != nil {
		t.Fatal(e)
	}
	response, e := client.HTTP.Get(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if client.APICAFile != path {
		t.Fatal("CA file path not preserved")
	}
	// A different hostname must still be rejected even when using this CA.
	original := client.HTTP.Transport.(*http.Transport).TLSClientConfig
	if original.InsecureSkipVerify || original.RootCAs == nil {
		t.Fatal("TLS verification disabled")
	}
	wrongHost := client.HTTP.Transport.(*http.Transport).Clone()
	wrongHost.TLSClientConfig = original.Clone()
	wrongHost.TLSClientConfig.ServerName = "wrong-host.example.test"
	client.HTTP.Transport = wrongHost
	if response, e = client.HTTP.Get(server.URL); e == nil {
		response.Body.Close()
		t.Fatal("hostname verification bypassed")
	}
	wrongHost.CloseIdleConnections()

	// Unknown or malformed CA contents fail rather than falling back insecurely.
	if e = os.WriteFile(path, []byte("not PEM"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = client.configureAPITrust(path); e == nil {
		t.Fatal("malformed CA accepted")
	}
}
