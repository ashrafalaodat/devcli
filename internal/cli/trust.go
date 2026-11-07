package cli

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// configureAPITrust appends an explicitly configured public CA bundle while
// retaining system roots and hostname verification. This applies only to the
// devctl control API; the gateway public CA is embedded in generated kubeconfigs.
func (c *Client) configureAPITrust(path string) error {
	if path == "" {
		c.APICAFile = ""
		return nil
	}
	absolute, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	file, e := os.Open(absolute)
	if e != nil {
		return errors.New("cannot read DEVCTL_API_CA_FILE")
	}
	defer file.Close()
	raw, e := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 {
		return errors.New("DEVCTL_API_CA_FILE must be a public PEM bundle at most 1 MiB")
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		return errors.New("cannot load system certificate roots")
	}
	if !roots.AppendCertsFromPEM(raw) {
		return errors.New("DEVCTL_API_CA_FILE contains no valid CA certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	c.HTTP.Transport = transport
	c.APICAFile = absolute
	return nil
}
