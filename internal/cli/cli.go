package cli

import (
	"bytes"
	"context"
	"devctl.local/devctl/internal/auth"
	"devctl.local/devctl/internal/model"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"io"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"
)

type ExitError struct {
	Code int
	Err  error
}

type apiStatusError struct {
	Status  int
	Message string
}

func (e *apiStatusError) Error() string { return e.Message }

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

type Client struct {
	URL       string
	APICAFile string
	Login     *loginStore
	HTTP      *http.Client
	JSON      bool
	Out, Err  io.Writer
}

func (c *Client) request(ctx context.Context, method, path string, body any, key string, out any) error {
	token, e := c.Login.token(ctx)
	if e != nil {
		return &ExitError{3, e}
	}
	return c.withToken(ctx, token.AccessToken, method, path, body, key, out)
}
func (c *Client) withToken(ctx context.Context, token, method, path string, body any, key string, out any) error {
	var raw []byte
	var e error
	if body != nil {
		raw, e = json.Marshal(body)
		if e != nil {
			return e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, c.URL+path, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, e := c.HTTP.Do(req)
	if e != nil {
		return errors.New("backend unavailable; check DEVCTL_API and network")
	}
	defer resp.Body.Close()
	data, e := io.ReadAll(io.LimitReader(resp.Body, 3<<20))
	if e != nil {
		return e
	}
	if resp.StatusCode/100 != 2 {
		var msg struct {
			Error string `json:"error"`
		}
		json.Unmarshal(data, &msg)
		if msg.Error == "" {
			msg.Error = http.StatusText(resp.StatusCode)
		}
		code := 1
		switch resp.StatusCode {
		case 401, 403:
			code = 3
		case 409:
			code = 4
		case 404:
			code = 5
		}
		return &ExitError{code, &apiStatusError{Status: resp.StatusCode, Message: msg.Error}}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
func (c *Client) print(v any) error {
	encoder := json.NewEncoder(c.Out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}
func labelMap(raw []string) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range raw {
		k, val, ok := strings.Cut(v, "=")
		if !ok || k == "" || val == "" {
			return nil, errors.New("labels must be key=value")
		}
		out[k] = val
	}
	return out, nil
}
func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func NewCommand() *cobra.Command {
	c := &Client{HTTP: &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Out: os.Stdout, Err: os.Stderr}
	return newCommand(c)
}

func newCommand(c *Client) *cobra.Command {
	var apiURL string
	root := &cobra.Command{Use: "devctl", Short: "Book a cluster and access it through the devctl gateway", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().StringVar(&apiURL, "api", env("DEVCTL_API", "https://127.0.0.1:9090"), "Backend URL")
	root.PersistentFlags().BoolVar(&c.JSON, "json", false, "Print machine-readable JSON (kubeconfig always prints only its path)")
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		u, e := url.Parse(apiURL)
		if e != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return errors.New("invalid API URL")
		}
		if u.Scheme != "https" && (u.Scheme != "http" || u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") {
			return errors.New("API requires HTTPS except on loopback")
		}
		c.URL = strings.TrimRight(apiURL, "/")
		cfg := auth.DefaultConfig(env("DEVCTL_ISSUER", "http://127.0.0.1:8081/realms/devctl"))
		if raw := os.Getenv("DEVCTL_OIDC_CONFIG"); raw != "" {
			if e = json.Unmarshal([]byte(raw), &cfg); e != nil {
				return e
			}
		}
		if !strings.HasPrefix(cfg.Issuer, "https://") && os.Getenv("DEVCTL_DEV_HTTP") != "1" {
			return errors.New("OIDC requires HTTPS; explicitly enable DEVCTL_DEV_HTTP=1 for local demo")
		}
		if e = c.configureAPITrust(os.Getenv("DEVCTL_API_CA_FILE")); e != nil {
			return e
		}
		c.Login, e = newLoginStore(c.URL, cfg)
		return e
	}
	root.AddCommand(&cobra.Command{Use: "login", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
		defer cancel()
		if e := c.Login.login(ctx, c.Err); e != nil {
			return e
		}
		var identity model.Identity
		if e := c.request(ctx, "GET", "/v1/whoami", nil, "", &identity); e != nil {
			c.Login.clear()
			return e
		}
		if _, err := c.setupGateway(ctx); err != nil {
			return err
		}
		return c.print(identity)
	}})
	root.AddCommand(&cobra.Command{Use: "whoami", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		var out model.Identity
		if e := c.request(cmd.Context(), "GET", "/v1/whoami", nil, "", &out); e != nil {
			return e
		}
		return c.print(out)
	}})
	root.AddCommand(&cobra.Command{Use: "clusters", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		var cs []model.Cluster
		if e := c.request(cmd.Context(), "GET", "/v1/clusters", nil, "", &cs); e != nil {
			return e
		}
		if c.JSON {
			return c.print(cs)
		}
		w := tabwriter.NewWriter(c.Out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tAVAILABLE\tSHAREABLE\tHOLDERS\tLABELS")
		for _, v := range cs {
			names := []string{}
			for _, s := range v.Participants {
				names = append(names, s.DisplayName+" <"+s.Email+">")
			}
			labels, _ := json.Marshal(v.Labels)
			fmt.Fprintf(w, "%s\t%s\t%t\t%t\t%s\t%s\n", v.ID, v.Name, v.Available, v.Shareable, strings.Join(names, ", "), labels)
		}
		return w.Flush()
	}})
	var cluster, idempotency string
	var selectors []string
	start := &cobra.Command{Use: "start", Short: "Book a whole cluster; exclusive unless its holder enabled sharing", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		labels, e := labelMap(selectors)
		if e != nil {
			return e
		}
		key := idempotency
		if key == "" {
			key = uuid.NewString()
		}
		fmt.Fprintln(c.Err, "Request idempotency key:", key)
		var out model.Session
		e = c.request(cmd.Context(), "POST", "/v1/sessions", model.Booking{Cluster: cluster, Selector: labels}, key, &out)
		if e != nil {
			return e
		}
		if _, e = c.setupGateway(cmd.Context()); e != nil {
			return fmt.Errorf("booking %s exists, but writing the stable gateway configuration failed: %w", out.ID, e)
		}
		fmt.Fprintln(c.Err, "Cluster booked. Your first booking becomes primary; additional bookings do not change the current primary.")
		return c.print(out)
	}}
	start.Flags().StringVar(&cluster, "cluster", "", "Cluster ID or display name (otherwise automatic selection)")
	start.Flags().StringSliceVarP(&selectors, "selector", "l", nil, "Required labels, e.g. region=eu,type=test")
	start.Flags().StringVar(&idempotency, "idempotency-key", "", "Reuse this key when retrying a booking request")
	root.AddCommand(start)
	var all bool
	sessions := &cobra.Command{Use: "sessions", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		var ss []model.Session
		if e := c.request(cmd.Context(), "GET", "/v1/sessions", nil, "", &ss); e != nil {
			return e
		}
		if !all {
			var u model.Identity
			if e := c.request(cmd.Context(), "GET", "/v1/whoami", nil, "", &u); e != nil {
				return e
			}
			filtered := []model.Session{}
			for _, v := range ss {
				if v.Owner == u.Key() {
					filtered = append(filtered, v)
				}
			}
			ss = filtered
		}
		if c.JSON {
			return c.print(ss)
		}
		return c.printSessionTable(ss)
	}}
	sessions.Flags().BoolVar(&all, "all", false, "Show team bookings and contact details")
	root.AddCommand(sessions)
	root.AddCommand(&cobra.Command{Use: "status [SESSION_ID]", Short: "Show bookings and their inactivity auto-release deadlines", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 1 {
			var out struct {
				Session model.Session `json:"session"`
				Cluster model.Cluster `json:"cluster"`
			}
			if e := c.request(cmd.Context(), "GET", sessionPath(args[0]), nil, "", &out); e != nil {
				return e
			}
			if c.JSON {
				return c.print(out)
			}
			return c.printSessionTable([]model.Session{out.Session})
		}
		var out developerProfile
		if e := c.request(cmd.Context(), "GET", "/v1/profile", nil, "", &out); e != nil {
			return e
		}
		return c.printProfile(out)
	}})
	root.AddCommand(&cobra.Command{Use: "wait SESSION_ID", Short: "Check a booking (this version rejects conflicts rather than queueing)", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var out struct {
			Session model.Session `json:"session"`
		}
		if e := c.request(cmd.Context(), "GET", sessionPath(args[0]), nil, "", &out); e != nil {
			return e
		}
		if out.Session.State != "ACTIVE" {
			return &ExitError{4, errors.New("booking is " + out.Session.State)}
		}
		return c.print(out.Session)
	}})
	var disable bool
	share := &cobra.Command{Use: "share SESSION_ID", Short: "Allow another developer to book this cluster (controller only)", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var out any
		if e := c.request(cmd.Context(), "POST", sessionPath(args[0])+"/share", map[string]bool{"shareable": !disable}, "", &out); e != nil {
			return e
		}
		return c.print(out)
	}}
	share.Flags().BoolVar(&disable, "off", false, "Block new participants; keep current bookings")
	root.AddCommand(share)
	root.AddCommand(&cobra.Command{Use: "stop SESSION_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var out any
		if e := c.request(cmd.Context(), "POST", sessionPath(args[0])+"/stop", nil, "", &out); e != nil {
			return e
		}
		fmt.Fprintln(c.Err, "Booking released. The stable gateway follows your remaining primary booking, if any. Cluster workloads were not deleted.")
		return c.print(out)
	}})
	root.AddCommand(&cobra.Command{Use: "kubeconfig", Short: "Write your stable gateway kubeconfig and print ONLY its path", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		path, e := c.download(cmd.Context())
		if e != nil {
			return e
		}
		fmt.Fprintln(c.Out, path)
		return nil
	}})
	root.AddCommand(&cobra.Command{Use: "exec -- COMMAND [ARGS...]", DisableFlagParsing: true, RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 || args[0] != "--" {
			return &ExitError{2, errors.New("usage: devctl exec -- COMMAND [ARGS...]")}
		}
		path, e := c.download(cmd.Context())
		if e != nil {
			return e
		}
		child := exec.CommandContext(cmd.Context(), args[1], args[2:]...)
		child.Stdin = os.Stdin
		child.Stdout = c.Out
		child.Stderr = c.Err
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "KUBECONFIG=") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "KUBECONFIG="+path)
		if e = child.Run(); e != nil {
			var exit *exec.ExitError
			if errors.As(e, &exit) {
				return &ExitError{exit.ExitCode(), errors.New("child process failed")}
			}
			return e
		}
		return nil
	}})
	root.AddCommand(&cobra.Command{Use: "logout", Short: "Release bookings and clear SSO login without revoking PATs", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 45*time.Second)
		defer cancel()
		t, tokenErr := c.Login.token(ctx)
		var releaseErr error
		if tokenErr == nil {
			releaseErr = c.withToken(ctx, t.AccessToken, "POST", "/v1/logout", nil, "", nil)
		} else {
			releaseErr = tokenErr
		}
		if releaseErr != nil {
			fmt.Fprintln(c.Err, "Warning: could not release bookings; they may remain active. Log in again to stop them.")
		}
		unlock, e := c.Login.lock(ctx)
		if e != nil {
			return e
		}
		defer unlock()
		stored, e := c.Login.read()
		if e == nil {
			if e = c.Login.revoke(ctx, stored); e != nil {
				fmt.Fprintln(c.Err, "Warning:", e)
			}
		}
		if e = c.Login.clear(); e != nil {
			return e
		}
		files, _ := filepath.Glob(filepath.Join(c.Login.Dir, "s-*.yaml"))
		for _, p := range files {
			os.Remove(p)
		}
		if e = c.clearActive(ctx); e != nil {
			return e
		}
		fmt.Fprintln(c.Err, "Local login cleared; gateway configuration is inactive. Previously distributed original cluster credentials are not revoked.")
		if releaseErr != nil {
			return releaseErr
		}
		return c.print(map[string]string{"status": "logged out; bookings released; personal access tokens preserved"})
	}})
	c.addGatewayCommands(root)
	c.addAdmin(root)
	c.addPATCommands(root)
	return root
}
func sessionPath(id string) string { return "/v1/sessions/" + url.PathEscape(id) }

var sessionID = regexp.MustCompile(`^s-[a-f0-9-]{36}$`)

func (c *Client) addAdmin(root *cobra.Command) {
	admin := &cobra.Command{Use: "admin", Short: "Administrator registry operations (no Kubernetes API calls)"}
	var id, name, file, contextName string
	var labels []string
	var maxParticipants int
	register := &cobra.Command{Use: "register", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		ls, e := labelMap(labels)
		if e != nil {
			return e
		}
		cfg, e := clientcmd.LoadFromFile(file)
		if e != nil {
			return errors.New("cannot read kubeconfig")
		}
		if contextName != "" {
			cfg.CurrentContext = contextName
		}
		if e = clientapi.MinifyConfig(cfg); e != nil {
			return errors.New("cannot select kubeconfig context")
		}
		if e = clientapi.FlattenConfig(cfg); e != nil {
			return errors.New("cannot embed referenced kubeconfig certificate files")
		}
		raw, e := clientcmd.Write(*cfg)
		if e != nil {
			return e
		}
		var out any
		e = c.request(cmd.Context(), "POST", "/v1/admin/clusters", map[string]any{"id": id, "name": name, "labels": ls, "max_participants": maxParticipants, "kubeconfig": string(raw)}, "", &out)
		if e != nil {
			return e
		}
		return c.print(out)
	}}
	register.Flags().StringVar(&id, "id", "", "Stable cluster ID")
	register.Flags().StringVar(&name, "name", "", "Display name")
	register.Flags().StringVar(&file, "kubeconfig", "", "Existing kubeconfig file to encrypt in database")
	register.Flags().StringVar(&contextName, "context", "", "Context to import (defaults to current context)")
	register.Flags().StringSliceVarP(&labels, "label", "l", nil, "Cluster labels key=value")
	register.Flags().IntVar(&maxParticipants, "max-participants", 2, "Maximum simultaneous holders after sharing is enabled")
	register.MarkFlagRequired("id")
	register.MarkFlagRequired("name")
	register.MarkFlagRequired("kubeconfig")
	admin.AddCommand(register)
	var maintenance bool
	var reason string
	maintain := &cobra.Command{Use: "maintenance CLUSTER_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if reason == "" {
			return errors.New("--reason required")
		}
		var out any
		if e := c.request(cmd.Context(), "PATCH", "/v1/admin/clusters/"+url.PathEscape(args[0]), map[string]any{"maintenance": maintenance, "reason": reason}, "", &out); e != nil {
			return e
		}
		return c.print(out)
	}}
	maintain.Flags().BoolVar(&maintenance, "enabled", true, "Disable new bookings")
	maintain.Flags().StringVar(&reason, "reason", "", "Audit reason")
	admin.AddCommand(maintain)
	var forceReason string
	force := &cobra.Command{Use: "release SESSION_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if forceReason == "" {
			return errors.New("--reason required")
		}
		var out any
		if e := c.request(cmd.Context(), "POST", "/v1/admin/sessions/"+url.PathEscape(args[0])+"/release", map[string]string{"reason": forceReason}, "", &out); e != nil {
			return e
		}
		return c.print(out)
	}}
	force.Flags().StringVar(&forceReason, "reason", "", "Audit reason")
	admin.AddCommand(force)
	c.addPolicyCommands(admin)
	root.AddCommand(admin)
}
