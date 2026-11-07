// Package kube validates and encrypts server-held Kubernetes credentials.
package kube

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"k8s.io/client-go/tools/clientcmd"
	"net/url"
)

// Validate accepts a single static, portable context. Executable credential plugins
// and file references are deliberately excluded from centrally delivered configs.
func Validate(raw []byte) error {
	c, e := clientcmd.Load(raw)
	if e != nil {
		return errors.New("invalid kubeconfig YAML")
	}
	if len(c.Contexts) != 1 || len(c.Clusters) != 1 || len(c.AuthInfos) != 1 {
		return errors.New("import exactly one context, cluster and user (kubectl config view --minify --flatten --raw)")
	}
	if e = clientcmd.Validate(*c); e != nil {
		return errors.New("incomplete kubeconfig")
	}
	for _, v := range c.Clusters {
		u, e := url.Parse(v.Server)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || v.InsecureSkipTLSVerify || v.CertificateAuthority != "" || v.ProxyURL != "" {
			return errors.New("HTTPS with verified TLS, embedded CA and no proxy override required")
		}
	}
	for _, v := range c.AuthInfos {
		if v.Exec != nil || v.AuthProvider != nil || v.TokenFile != "" || v.ClientCertificate != "" || v.ClientKey != "" || v.Username != "" || v.Password != "" || v.Impersonate != "" || v.ImpersonateUID != "" || len(v.ImpersonateGroups) > 0 || len(v.ImpersonateUserExtra) > 0 {
			return errors.New("only embedded static token or client certificate credentials are supported")
		}
		if v.Token == "" && (len(v.ClientCertificateData) == 0 || len(v.ClientKeyData) == 0) {
			return errors.New("static token or client certificate/key required")
		}
	}
	return nil
}

type Vault struct{ aead cipher.AEAD }

func NewVault(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, errors.New("DEVCTL_MASTER_KEY must be base64-encoded 32 random bytes")
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	return &Vault{a}, e
}
func (v *Vault) Seal(id string, raw []byte) ([]byte, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return nil, e
	}
	return v.aead.Seal(nonce, nonce, raw, []byte(id)), nil
}
func (v *Vault) Open(id string, encrypted []byte) ([]byte, error) {
	n := v.aead.NonceSize()
	if len(encrypted) < n {
		return nil, errors.New("invalid encrypted kubeconfig")
	}
	return v.aead.Open(nil, encrypted[:n], encrypted[n:], []byte(id))
}

// PublicCertificates rejects mixed PEM bundles so a misconfigured gateway CA
// file can never distribute a private key through connection metadata.
func PublicCertificates(raw []byte) ([]byte, error) {
	var out []byte
	for len(bytes.TrimSpace(raw)) > 0 {
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("gateway CA file must contain only PEM certificates")
		}
		if _, e := x509.ParseCertificate(block.Bytes); e != nil {
			return nil, errors.New("invalid gateway CA certificate")
		}
		out = append(out, pem.EncodeToMemory(block)...)
		raw = rest
	}
	if len(out) == 0 {
		return nil, errors.New("empty gateway CA file")
	}
	return out, nil
}
