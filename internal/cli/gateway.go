package cli

import (
	"context"
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

func (c *Client) connection(ctx context.Context, id string) (Connection, error) {
	var out Connection
	if !sessionID.MatchString(id) {
		return out, errors.New("invalid session ID")
	}
	if e := c.request(ctx, "GET", sessionPath(id)+"/connection", nil, "", &out); e != nil {
		return out, e
	}
	if e := validateConnection(out); e != nil {
		return out, e
	}
	return out, nil
}

func validateConnection(connection Connection) error {
	u, e := url.Parse(connection.Server)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("backend returned an invalid gateway URL")
	}
	if u.Scheme != "https" {
		return errors.New("Kubernetes gateway requires HTTPS, including on loopback")
	}
	return nil
}

func (c *Client) gatewayConfig(id string, connection Connection) ([]byte, error) {
	if e := validateConnection(connection); e != nil {
		return nil, e
	}
	if !sessionID.MatchString(id) {
		return nil, errors.New("invalid session ID")
	}
	executable, e := os.Executable()
	if e != nil {
		return nil, e
	}
	executable, e = filepath.Abs(executable)
	if e != nil {
		return nil, e
	}
	ca, e := base64.StdEncoding.DecodeString(connection.CertificateAuthorityData)
	if e != nil {
		return nil, errors.New("backend returned an invalid gateway CA")
	}
	cfg := clientapi.NewConfig()
	cfg.CurrentContext = id
	cfg.Clusters["devctl"] = &clientapi.Cluster{Server: connection.Server, CertificateAuthorityData: ca}
	cfg.Contexts[id] = &clientapi.Context{Cluster: "devctl", AuthInfo: "devctl"}
	env, e := c.executionEnvironment()
	if e != nil {
		return nil, e
	}
	cfg.AuthInfos["devctl"] = &clientapi.AuthInfo{Exec: &clientapi.ExecConfig{
		APIVersion: "client.authentication.k8s.io/v1", Command: executable,
		Args: []string{"--api", c.URL, "credential", "--session", id}, Env: env,
		InteractiveMode: clientapi.NeverExecInteractiveMode,
	}}
	return clientcmd.Write(*cfg)
}

func (c *Client) download(ctx context.Context, id string) (string, error) {
	path, e := c.configPath(id)
	if e != nil {
		return "", e
	}
	connection, e := c.connection(ctx, id)
	if e != nil {
		return "", e
	}
	raw, e := c.gatewayConfig(id, connection)
	if e != nil {
		return "", e
	}
	if e = atomicPrivate(path, raw); e != nil {
		return "", e
	}
	return path, nil
}

func (c *Client) credential(ctx context.Context, id string) error {
	if !sessionID.MatchString(id) {
		return errors.New("invalid session ID")
	}
	t, e := c.Login.token(ctx)
	if e != nil {
		return &ExitError{3, e}
	}
	// This backend check authenticates the current application identity and confirms
	// ownership and live booking state before the token is returned to kubectl.
	var metadata Connection
	if e = c.withToken(ctx, t.AccessToken, "GET", sessionPath(id)+"/connection", nil, "", &metadata); e != nil {
		return e
	}
	if t.Expiry.IsZero() || !t.Expiry.After(time.Now()) || t.AccessToken == "" {
		return &ExitError{3, errors.New("login has no valid token expiry; run devctl login")}
	}
	return json.NewEncoder(c.Out).Encode(map[string]any{
		"apiVersion": "client.authentication.k8s.io/v1", "kind": "ExecCredential",
		"status": map[string]string{"token": t.AccessToken, "expirationTimestamp": t.Expiry.UTC().Format(time.RFC3339Nano)},
	})
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

func (c *Client) selectSession(ctx context.Context, id string) (string, error) {
	path, e := c.download(ctx, id)
	if e != nil {
		return "", e
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	unlock, e := c.selectionLock(ctx)
	if e != nil {
		return "", e
	}
	defer unlock()
	if e = atomicPrivate(c.activePath(), raw); e != nil {
		return "", e
	}
	return c.activePath(), nil
}

// Keep a deliberately inactive kubeconfig instead of removing the path. Shells
// remain pointed at devctl and never accidentally fall back to ~/.kube/config.
var inactiveConfig = []byte("apiVersion: v1\nkind: Config\ncurrent-context: devctl-no-active-session\nclusters: []\nusers: []\ncontexts: []\n")

func (c *Client) clearActive(ctx context.Context, id string) error {
	unlock, e := c.selectionLock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
	if id != "" {
		raw, e := os.ReadFile(c.activePath())
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return e
		}
		cfg, e := clientcmd.Load(raw)
		if e != nil {
			return errors.New("active gateway configuration cannot be read")
		}
		if cfg.CurrentContext != id {
			return nil
		}
	}
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
	// from switching the credential plugin to a different login/profile.
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
	var session string
	credential := &cobra.Command{Use: "credential", Short: "Kubernetes exec credential plugin for the devctl gateway", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return c.credential(cmd.Context(), session) }}
	credential.Flags().StringVar(&session, "session", "", "Active session ID")
	credential.MarkFlagRequired("session")
	root.AddCommand(credential)
	root.AddCommand(&cobra.Command{Use: "select SESSION_ID", Short: "Select gateway access for every shell using this profile", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		path, e := c.selectSession(cmd.Context(), args[0])
		if e != nil {
			return e
		}
		return c.print(map[string]string{"session": args[0], "kubeconfig": path})
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
