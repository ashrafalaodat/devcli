package cli

import (
	"context"
	"devctl.local/devctl/internal/kube"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

// Connection contains public gateway metadata, never the upstream kubeconfig.
type Connection struct {
	Server                   string `json:"server"`
	CertificateAuthorityData string `json:"certificate_authority_data,omitempty"`
}

func (c *Client) connection(ctx context.Context) (Connection, error) {
	var out Connection
	if err := c.request(ctx, "GET", "/v1/connection", nil, "", &out); err != nil {
		return out, err
	}
	if err := validateConnection(out); err != nil {
		return out, err
	}
	return out, nil
}

func validateConnection(connection Connection) error {
	u, err := url.Parse(connection.Server)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Scheme != "https" || u.Path != "/k8s" {
		return errors.New("backend must return a stable HTTPS gateway URL ending in /k8s")
	}
	return nil
}

func (c *Client) gatewayConfig(connection Connection) ([]byte, error) {
	if err := validateConnection(connection); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return nil, err
	}
	ca, err := base64.StdEncoding.DecodeString(connection.CertificateAuthorityData)
	if err != nil {
		return nil, errors.New("backend returned an invalid gateway CA")
	}
	if len(ca) > 0 {
		ca, err = kube.PublicCertificates(ca)
		if err != nil {
			return nil, err
		}
	}
	vars, err := c.executionEnvironment()
	if err != nil {
		return nil, err
	}
	cfg := clientapi.NewConfig()
	cfg.CurrentContext = "devctl"
	cfg.Clusters["devctl"] = &clientapi.Cluster{Server: connection.Server, CertificateAuthorityData: ca}
	cfg.Contexts["devctl"] = &clientapi.Context{Cluster: "devctl", AuthInfo: "devctl"}
	cfg.AuthInfos["devctl"] = &clientapi.AuthInfo{Exec: &clientapi.ExecConfig{APIVersion: "client.authentication.k8s.io/v1", Command: executable, Args: []string{"--api", c.URL, "credential"}, Env: vars, InteractiveMode: clientapi.IfAvailableExecInteractiveMode}}
	return clientcmd.Write(*cfg)
}

// download refreshes public metadata at one stable path. It never selects or
// books a cluster and never downloads the original cluster credentials.
func (c *Client) download(ctx context.Context) (string, error) {
	connection, err := c.connection(ctx)
	if err != nil {
		return "", err
	}
	return c.writeGatewayConfig(ctx, connection)
}

func (c *Client) writeGatewayConfig(ctx context.Context, connection Connection) (string, error) {
	raw, err := c.gatewayConfig(connection)
	if err != nil {
		return "", err
	}
	unlock, err := c.selectionLock(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()
	if err = atomicPrivate(c.activePath(), raw); err != nil {
		return "", err
	}
	legacy := filepath.Join(c.Login.Dir, "auto-binding.json")
	if info, e := os.Lstat(legacy); e == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("legacy binding must be a regular file; remove it manually")
		}
		if e = os.Remove(legacy); e != nil {
			return "", e
		}
	} else if !os.IsNotExist(e) {
		return "", e
	}
	return c.activePath(), nil
}

func (c *Client) activePath() string { return filepath.Join(c.Login.Dir, "active-kubeconfig") }

func (c *Client) selectionLock(ctx context.Context) (func(), error) {
	lock := flock.New(filepath.Join(c.Login.Dir, "selection.lock"))
	ok, e := lock.TryLockContext(ctx, 50*time.Millisecond)
	if e != nil {
		return nil, e
	}
	if !ok {
		return nil, errors.New("cannot lock active selection")
	}
	return func() { lock.Unlock() }, nil
}

// Keep a deliberately inactive kubeconfig instead of removing the path. Shells
// remain pointed at devctl and never accidentally fall back to ~/.kube/config.
var inactiveConfig = []byte("apiVersion: v1\nkind: Config\ncurrent-context: devctl-no-active-session\nclusters: []\nusers: []\ncontexts: []\n")

func (c *Client) clearActive(ctx context.Context) error {
	unlock, err := c.selectionLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return atomicPrivate(c.activePath(), inactiveConfig)
}

func (c *Client) ensureActivePath(ctx context.Context) error {
	unlock, e := c.selectionLock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
	info, e := os.Lstat(c.activePath())
	if os.IsNotExist(e) {
		return atomicPrivate(c.activePath(), inactiveConfig)
	}
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return errors.New("active kubeconfig must be a regular file")
	}
	return nil
}

func shellName(value string) (string, error) {
	if value == "" {
		value = filepath.Base(os.Getenv("SHELL"))
		if value == "" || value == "." {
			value = "bash"
		}
	}
	switch value {
	case "bash", "zsh", "fish":
		return value, nil
	}
	return "", errors.New("supported shells are bash, zsh, and fish; set --shell")
}
func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

// Fish interprets backslash escapes inside single quotes, unlike POSIX shells.
func fishQuote(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "'", "\\'")
	return "'" + value + "'"
}

func (c *Client) executionEnvironment() ([]clientapi.ExecEnvVar, error) {
	oidc, e := json.Marshal(c.Login.Config)
	if e != nil {
		return nil, e
	}
	// Explicit nonsecret configuration prevents a new shell's unrelated defaults
	// from switching the credential helper to a different login/profile.
	vars := []clientapi.ExecEnvVar{
		{Name: "DEVCTL_CONFIG_DIR", Value: filepath.Dir(c.Login.Dir)},
		{Name: "DEVCTL_OIDC_CONFIG", Value: string(oidc)},
		{Name: "DEVCTL_ISSUER", Value: c.Login.Config.Issuer},
		{Name: "DEVCTL_DEV_HTTP", Value: "0"},
		{Name: "DEVCTL_DEV_TOKEN_FILE", Value: "0"},
		{Name: "DEVCTL_API_CA_FILE", Value: c.APICAFile},
	}
	if os.Getenv("DEVCTL_DEV_HTTP") == "1" {
		vars[3].Value = "1"
	}
	if c.Login.DevFile {
		vars[4].Value = "1"
	}
	return vars, nil
}

func (c *Client) shellInit(ctx context.Context, shell string) (string, error) {
	shell, e := shellName(shell)
	if e != nil {
		return "", e
	}
	if e = c.ensureActivePath(ctx); e != nil {
		return "", e
	}
	vars, e := c.executionEnvironment()
	if e != nil {
		return "", e
	}
	vars = append(vars, clientapi.ExecEnvVar{Name: "DEVCTL_API", Value: c.URL}, clientapi.ExecEnvVar{Name: "KUBECONFIG", Value: c.activePath()})
	var snippet strings.Builder
	for _, v := range vars {
		if shell == "fish" {
			fmt.Fprintf(&snippet, "set -gx %s %s\n", v.Name, fishQuote(v.Value))
		} else {
			fmt.Fprintf(&snippet, "export %s=%s\n", v.Name, shellQuote(v.Value))
		}
	}
	return snippet.String(), nil
}

const shellBlockStart = "# >>> devctl gateway >>>"
const shellBlockEnd = "# <<< devctl gateway <<<"

func updateShellRC(raw []byte, snippet string) ([]byte, error) {
	text := string(raw)
	start := strings.Index(text, shellBlockStart)
	end := strings.Index(text, shellBlockEnd)
	block := shellBlockStart + "\n" + snippet + shellBlockEnd + "\n"
	if start < 0 && end < 0 {
		if len(text) > 0 && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		return []byte(text + block), nil
	}
	if start < 0 || end < start || strings.Count(text, shellBlockStart) != 1 || strings.Count(text, shellBlockEnd) != 1 ||
		(start > 0 && text[start-1] != '\n') ||
		start+len(shellBlockStart) >= len(text) || text[start+len(shellBlockStart)] != '\n' ||
		(end > 0 && text[end-1] != '\n') ||
		(end+len(shellBlockEnd) < len(text) && text[end+len(shellBlockEnd)] != '\n') {
		return nil, errors.New("shell rc has an incomplete or duplicate devctl block; repair it before installing")
	}
	end += len(shellBlockEnd)
	if end < len(text) && text[end] == '\n' {
		end++
	}
	return []byte(text[:start] + block + text[end:]), nil
}

func (c *Client) installShell(ctx context.Context, shell, rcFile string) (string, error) {
	shell, e := shellName(shell)
	if e != nil {
		return "", e
	}
	if rcFile == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", e
		}
		switch shell {
		case "bash":
			rcFile = filepath.Join(home, ".bashrc")
		case "zsh":
			dotdir := os.Getenv("ZDOTDIR")
			if dotdir == "" {
				dotdir = home
			}
			rcFile = filepath.Join(dotdir, ".zshrc")
		case "fish":
			root := os.Getenv("XDG_CONFIG_HOME")
			if root == "" {
				root = filepath.Join(home, ".config")
			}
			rcFile = filepath.Join(root, "fish", "conf.d", "devctl.fish")
		}
	}
	rcFile, e = filepath.Abs(rcFile)
	if e != nil {
		return "", e
	}
	if info, e := os.Lstat(rcFile); e == nil && !info.Mode().IsRegular() {
		return "", errors.New("shell rc must be a regular file; symlinks are not overwritten")
	} else if e != nil && !os.IsNotExist(e) {
		return "", e
	}
	snippet, e := c.shellInit(ctx, shell)
	if e != nil {
		return "", e
	}
	raw, e := os.ReadFile(rcFile)
	if e != nil && !os.IsNotExist(e) {
		return "", e
	}
	next, e := updateShellRC(raw, snippet)
	if e != nil {
		return "", e
	}
	if string(next) == string(raw) {
		return rcFile, nil
	}
	if e = os.MkdirAll(filepath.Dir(rcFile), 0700); e != nil {
		return "", e
	}
	// The RC may contain user secrets. Preserve its existing bytes and use a
	// tightly permissioned atomic replacement instead of creating an extra backup.
	if e = atomicPrivate(rcFile, next); e != nil {
		return "", e
	}
	return rcFile, nil
}

func (c *Client) addGatewayCommands(root *cobra.Command) {
	credential := &cobra.Command{Use: "credential", Short: "Kubernetes exec authentication for your current primary cluster", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return c.credential(cmd.Context()) }}
	root.AddCommand(credential)
	c.addAccessCommands(root)
	root.AddCommand(&cobra.Command{Use: "select CLUSTER", Short: "Switch your primary booked cluster for every client", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var profile developerProfile
		if err := c.request(cmd.Context(), "POST", "/v1/primary", map[string]string{"cluster": args[0]}, "", &profile); err != nil {
			return err
		}
		if _, err := c.setupGateway(cmd.Context()); err != nil {
			return err
		}
		return c.print(profile)
	}})

	shell := &cobra.Command{Use: "shell", Short: "Initialize or install user-wide gateway selection for a shell"}
	var initShell string
	init := &cobra.Command{Use: "init", Short: "Print shell code setting KUBECONFIG to this profile's active gateway configuration", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		snippet, e := c.shellInit(cmd.Context(), initShell)
		if e != nil {
			return e
		}
		_, e = fmt.Fprint(c.Out, snippet)
		return e
	}}
	init.Flags().StringVar(&initShell, "shell", "", "bash, zsh, or fish (defaults to SHELL)")
	shell.AddCommand(init)
	var installShell, rcFile string
	install := &cobra.Command{Use: "install", Short: "Add or update a bounded devctl block in the selected shell rc file", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		path, e := c.installShell(cmd.Context(), installShell, rcFile)
		if e != nil {
			return e
		}
		fmt.Fprintln(c.Err, "Installed devctl gateway selection. Source the rc file or open a new shell to activate it.")
		return c.print(map[string]string{"rc_file": path, "kubeconfig": c.activePath()})
	}}
	install.Flags().StringVar(&installShell, "shell", "", "bash, zsh, or fish (defaults to SHELL)")
	install.Flags().StringVar(&rcFile, "rc-file", "", "Explicit shell startup file (defaults to the selected shell's user rc)")
	shell.AddCommand(install)
	root.AddCommand(shell)
}
