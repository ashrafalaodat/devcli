package kube

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const Config = `apiVersion: v1
kind: Config
current-context: demo
clusters:
- name: demo
  cluster:
    server: https://127.0.0.1:6443
contexts:
- name: demo
  context:
    cluster: demo
    user: demo
users:
- name: demo
  user:
    token: development-test-token
`

func TestValidate(t *testing.T) {
	if e := Validate([]byte(Config)); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{strings.Replace(Config, "server: https:", "insecure-skip-tls-verify: true\n    server: https:", 1), strings.Replace(Config, "https:", "http:", 1), strings.Replace(Config, "token: development-test-token", "exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: dangerous", 1), strings.Replace(Config, "token: development-test-token", "tokenFile: /etc/secret", 1), strings.Replace(Config, "token: development-test-token", "username: admin\n    password: secret", 1), "not: [yaml"} {
		if e := Validate([]byte(raw)); e == nil {
			t.Fatal("unsafe config accepted")
		}
	}
}
func TestEncryption(t *testing.T) {
	v, e := NewVault(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	a, e := v.Seal("a", []byte(Config))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := v.Seal("a", []byte(Config))
	if bytes.Equal(a, b) || bytes.Contains(a, []byte("development-test-token")) {
		t.Fatal("encryption or random nonce failed")
	}
	out, e := v.Open("a", a)
	if e != nil || string(out) != Config {
		t.Fatal(e)
	}
	if _, e = v.Open("b", a); e == nil {
		t.Fatal("AAD swap accepted")
	}
	a[len(a)-1] ^= 1
	if _, e = v.Open("a", a); e == nil {
		t.Fatal("tamper accepted")
	}
	if _, e = NewVault([]byte("short")); e == nil {
		t.Fatal("weak key accepted")
	}
}

func TestGatewayCARejectsPrivateKeys(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	public, e := PublicCertificates(ca)
	if e != nil || !bytes.Equal(public, ca) {
		t.Fatal("public CA rejected", e)
	}
	for _, raw := range [][]byte{nil, []byte("not a certificate"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("do-not-publish")}), append(append([]byte{}, ca...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("do-not-publish")})...), append(append([]byte{}, ca...), []byte("trailing-secret")...)} {
		if out, e := PublicCertificates(raw); e == nil || out != nil {
			t.Fatal("secret or malformed CA file accepted")
		}
	}
}
