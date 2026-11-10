package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"github.com/gofrs/flock"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

var automaticID = regexp.MustCompile(`^a-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

const automaticIdleLimit = 2 * time.Minute

type automaticState struct {
	Binding string        `json:"binding"`
	Booking model.Booking `json:"booking"`
	Owner   string        `json:"owner,omitempty"`
}

type automaticAccess struct {
	Session struct {
		ID             string     `json:"id"`
		Owner          string     `json:"owner"`
		Cluster        string     `json:"cluster"`
		State          string     `json:"state"`
		ExpiresAt      *time.Time `json:"expires_at"`
		LastActivityAt *time.Time `json:"last_activity_at"`
	} `json:"session"`
	Server                   string    `json:"server"`
	CertificateAuthorityData string    `json:"certificate_authority_data"`
	AuthorizationExpiresAt   time.Time `json:"authorization_expires_at"`
}

func (c *Client) automaticStatePath() string          { return filepath.Join(c.Login.Dir, "auto-binding.json") }
func (c *Client) automaticPath(binding string) string { return "/v1/auto/" + binding }
func (c *Client) automaticServer(binding string) string {
	return strings.TrimSuffix(c.URL, "/") + "/k8s/auto/" + binding
}

func (c *Client) readAutomaticState() (automaticState, error) {
	var state automaticState
	info, err := os.Lstat(c.automaticStatePath())
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 64<<10 {
		return state, errors.New("automatic booking configuration must be a private regular file at most 64 KiB")
	}
	raw, err := os.ReadFile(c.automaticStatePath())
	if err != nil {
		return state, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&state); err != nil || decoder.Decode(new(any)) != io.EOF || !automaticID.MatchString(state.Binding) {
		return state, errors.New("invalid automatic booking configuration; run devctl setup explicitly")
	}
	return state, nil
}

func (c *Client) saveAutomaticState(state automaticState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicPrivate(c.automaticStatePath(), append(raw, '\n'))
}

func normalizeAutomaticBooking(booking model.Booking) (model.Booking, error) {
	if len(booking.Selector) == 0 {
		booking.Selector = nil
	}
	if booking.TTL != "" {
		ttl, err := time.ParseDuration(booking.TTL)
		if err != nil || ttl < time.Minute || ttl > 7*24*time.Hour {
			return booking, errors.New("TTL must be between 1m and 168h")
		}
		booking.TTL = ttl.String()
	}
	return booking, nil
}

// setupAutomatic only writes public connection/profile metadata. The first
// kubectl request, rather than setup, authenticates and allocates a booking.
func (c *Client) setupAutomatic(ctx context.Context, booking model.Booking, reset, replaceBooking bool) (string, error) {
	unlock, err := c.selectionLock(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()
	old, readErr := c.readAutomaticState()
	if readErr != nil && !os.IsNotExist(readErr) {
		return "", readErr
	}
	if readErr == nil && !replaceBooking {
		booking = old.Booking
	}
	booking, err = normalizeAutomaticBooking(booking)
	if err != nil {
		return "", err
	}
	state := old
	if readErr != nil || reset {
		state = automaticState{Binding: "a-" + uuid.NewString(), Booking: booking}
	} else {
		before, _ := json.Marshal(old.Booking)
		after, _ := json.Marshal(booking)
		if !bytes.Equal(before, after) {
			return "", errors.New("automatic booking selection changed; use --new-booking explicitly")
		}
	}
	raw, err := c.automaticKubeconfig(state.Binding)
	if err != nil {
		return "", err
	}
	if err = c.saveAutomaticState(state); err != nil {
		return "", err
	}
	if err = atomicPrivate(c.activePath(), raw); err != nil {
		return "", err
	}
	return c.activePath(), nil
}

func (c *Client) automaticKubeconfig(binding string) ([]byte, error) {
	connection := Connection{Server: c.automaticServer(binding)}
	if !automaticID.MatchString(binding) {
		return nil, errors.New("invalid automatic binding ID")
	}
	if err := validateConnection(connection); err != nil {
		return nil, err
	}
	var ca []byte
	if c.APICAFile != "" {
		file, err := os.Open(c.APICAFile)
		if err != nil {
			return nil, errors.New("cannot read the public gateway CA")
		}
		raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		file.Close()
		if err != nil || len(raw) > 1<<20 {
			return nil, errors.New("public gateway CA must be at most 1 MiB")
		}
		ca, err = kube.PublicCertificates(raw)
		if err != nil {
			return nil, err
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return nil, err
	}
	vars, err := c.executionEnvironment()
	if err != nil {
		return nil, err
	}
	cfg := clientapi.NewConfig()
	cfg.CurrentContext = binding
	cfg.Clusters["devctl"] = &clientapi.Cluster{Server: connection.Server, CertificateAuthorityData: ca}
	cfg.Contexts[binding] = &clientapi.Context{Cluster: "devctl", AuthInfo: "devctl"}
	cfg.AuthInfos["devctl"] = &clientapi.AuthInfo{Exec: &clientapi.ExecConfig{
		APIVersion: "client.authentication.k8s.io/v1", Command: executable,
		Args: []string{"--api", c.URL, "credential", "--auto", binding}, Env: vars,
		InteractiveMode: clientapi.IfAvailableExecInteractiveMode,
	}}
	return clientcmd.Write(*cfg)
}

func automaticInteractive() bool {
	raw := os.Getenv("KUBERNETES_EXEC_INFO")
	if len(raw) > 128<<10 {
		return false
	}
	var info struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			Interactive bool `json:"interactive"`
		} `json:"spec"`
	}
	return json.Unmarshal([]byte(raw), &info) == nil && info.APIVersion == "client.authentication.k8s.io/v1" &&
		info.Kind == "ExecCredential" && info.Spec.Interactive
}

func (c *Client) automaticToken(ctx context.Context, interactive bool, rejected string) (*oauth2.Token, error) {
	token, err := c.Login.token(ctx)
	if err == nil && token.AccessToken != rejected {
		return token, nil
	}
	if err != nil && !strings.Contains(err.Error(), "run devctl login") {
		return nil, err
	}
	if !interactive {
		return nil, &ExitError{3, errors.New("login is required; run kubectl from an interactive terminal or run devctl login explicitly")}
	}
	lock := flock.New(filepath.Join(c.Login.Dir, "auto-login.lock"))
	ok, err := lock.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("cannot lock interactive login")
	}
	defer lock.Unlock()
	// Another kubectl process may have finished the same login while we waited.
	token, err = c.Login.token(ctx)
	if err == nil && token.AccessToken != rejected {
		return token, nil
	}
	if err != nil && !strings.Contains(err.Error(), "run devctl login") {
		return nil, err
	}
	if err = c.Login.login(ctx, c.Err); err != nil {
		return nil, &ExitError{3, err}
	}
	token, err = c.Login.token(ctx)
	if err != nil {
		return nil, &ExitError{3, err}
	}
	var identity model.Identity
	if err = c.withToken(ctx, token.AccessToken, "GET", "/v1/whoami", nil, "", &identity); err != nil {
		// login() already saved the token under the auth lock. Remove rejected
		// credentials without exposing them to kubectl.
		unlock, lockErr := c.Login.lock(ctx)
		if lockErr == nil {
			current, readErr := c.Login.read()
			if readErr == nil && current.AccessToken == token.AccessToken {
				_ = c.Login.clear()
			}
			unlock()
		}
		return nil, err
	}
	return token, nil
}

func (c *Client) automaticCredential(ctx context.Context, binding string) error {
	if !automaticID.MatchString(binding) {
		return errors.New("invalid automatic binding ID")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	state, err := c.readAutomaticState()
	if err != nil {
		return err
	}
	if state.Binding != binding {
		return errors.New("automatic configuration was replaced; reload the selected kubeconfig")
	}
	interactive := automaticInteractive()
	token, err := c.automaticToken(ctx, interactive, "")
	if err != nil {
		return err
	}
	var identity model.Identity
	err = c.withToken(ctx, token.AccessToken, "GET", "/v1/whoami", nil, "", &identity)
	var status *apiStatusError
	if errors.As(err, &status) && status.Status == http.StatusUnauthorized {
		token, err = c.automaticToken(ctx, interactive, token.AccessToken)
		if err != nil {
			return err
		}
		err = c.withToken(ctx, token.AccessToken, "GET", "/v1/whoami", nil, "", &identity)
	}
	if err != nil {
		return err
	}
	unlock, err := c.selectionLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	state, err = c.readAutomaticState()
	if err != nil {
		return err
	}
	if state.Binding != binding {
		return errors.New("automatic configuration was replaced; reload the selected kubeconfig")
	}
	if state.Owner != "" && state.Owner != identity.Key() {
		return &ExitError{3, errors.New("this automatic profile belongs to a different login; use a separate DEVCTL_CONFIG_DIR or explicitly run devctl setup --new-booking")}
	}
	var access automaticAccess
	if err = c.withToken(ctx, token.AccessToken, "POST", c.automaticPath(binding)+"/ensure", state.Booking, "", &access); err != nil {
		return err
	}
	if access.Session.State != "ACTIVE" || !sessionID.MatchString(access.Session.ID) || access.Session.Owner != identity.Key() {
		return errors.New("backend did not return an active owned booking")
	}
	if err = validateConnection(Connection{Server: access.Server, CertificateAuthorityData: access.CertificateAuthorityData}); err != nil {
		return err
	}
	if access.Server != c.automaticServer(binding) {
		return errors.New("automatic setup requires the API and gateway to use the same public HTTPS origin; check --api and DEVCTL_PUBLIC_URL")
	}
	expiry := token.Expiry
	if access.AuthorizationExpiresAt.Before(expiry) {
		expiry = access.AuthorizationExpiresAt
	}
	if access.Session.ExpiresAt != nil && access.Session.ExpiresAt.Before(expiry) {
		expiry = *access.Session.ExpiresAt
	}
	if token.AccessToken == "" || expiry.IsZero() || !expiry.After(time.Now()) {
		return errors.New("backend did not return a valid authorization lifetime")
	}
	state.Owner = identity.Key()
	if err = c.saveAutomaticState(state); err != nil {
		return err
	}
	if err = c.startAutomaticHeartbeat(binding, access.Session.ID); err != nil {
		return fmt.Errorf("booking %s exists, but its renewal worker could not start: %w", access.Session.ID, err)
	}
	fmt.Fprintf(c.Err, "devctl: session %s on cluster %s\n", access.Session.ID, access.Session.Cluster)
	return json.NewEncoder(c.Out).Encode(map[string]any{
		"apiVersion": "client.authentication.k8s.io/v1", "kind": "ExecCredential",
		"status": map[string]string{"token": token.AccessToken, "expirationTimestamp": expiry.UTC().Format(time.RFC3339Nano)},
	})
}

func (c *Client) heartbeatLock(binding, session string) *flock.Flock {
	return flock.New(filepath.Join(c.Login.Dir, "heartbeat-"+binding+"-"+session+".lock"))
}

func (c *Client) startAutomaticHeartbeat(binding, session string) error {
	lock := c.heartbeatLock(binding, session)
	ok, err := lock.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	lock.Unlock()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.Command(executable, "--api", c.URL, "heartbeat", "--auto", binding, "--session", session)
	vars, err := c.executionEnvironment()
	if err != nil {
		return err
	}
	command.Env = append([]string(nil), os.Environ()...)
	for _, v := range vars {
		command.Env = append(command.Env, v.Name+"="+v.Value)
	}
	command.Env = append(command.Env, "DEVCTL_NO_BROWSER=1")
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer null.Close()
	command.Stdin, command.Stdout, command.Stderr = null, null, null
	configureAutomaticProcess(command)
	if err = command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

// The worker's own status requests are intentionally not activity. It exits when
// actual Kubernetes requests/streams stop, a booking ends, or the login changes.
func (c *Client) runAutomaticHeartbeat(ctx context.Context, binding, session string, interval time.Duration) error {
	if !automaticID.MatchString(binding) || !sessionID.MatchString(session) {
		return errors.New("invalid heartbeat binding or session")
	}
	lock := c.heartbeatLock(binding, session)
	ok, err := lock.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	defer lock.Unlock()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		state, err := c.readAutomaticState()
		if err != nil || state.Binding != binding {
			return nil
		}
		var access automaticAccess
		token, err := c.Login.token(ctx)
		if err != nil {
			return nil
		}
		if err = c.withToken(ctx, token.AccessToken, "GET", c.automaticPath(binding), nil, "", &access); err != nil {
			return nil
		}
		if access.Session.ID != session || access.Session.Owner != state.Owner || access.Session.State != "ACTIVE" ||
			access.Session.LastActivityAt == nil || time.Since(*access.Session.LastActivityAt) > automaticIdleLimit {
			return nil
		}
		if err = c.withToken(ctx, token.AccessToken, "POST", c.automaticPath(binding)+"/heartbeat", nil, "", &access); err != nil {
			return nil
		}
	}
}

func (c *Client) addAutomaticCommands(root *cobra.Command) {
	var cluster, ttl string
	var selectors []string
	var reset bool
	setup := &cobra.Command{Use: "setup", Short: "Prepare kubectl to log in and book automatically on first use", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		labels, err := labelMap(selectors)
		if err != nil {
			return err
		}
		replace := cmd.Flags().Changed("cluster") || cmd.Flags().Changed("selector") || cmd.Flags().Changed("ttl")
		path, err := c.setupAutomatic(cmd.Context(), model.Booking{Cluster: cluster, Selector: labels, TTL: ttl}, reset, replace)
		if err != nil {
			return err
		}
		fmt.Fprintln(c.Out, path)
		return nil
	}}
	setup.Flags().StringVar(&cluster, "cluster", "", "Cluster ID/name; omitted selects automatically")
	setup.Flags().StringSliceVarP(&selectors, "selector", "l", nil, "Required cluster labels")
	setup.Flags().StringVar(&ttl, "ttl", "", "Optional booking expiry from 1m through 168h")
	setup.Flags().BoolVar(&reset, "new-booking", false, "Explicitly reactivate with a fresh automatic binding")
	root.AddCommand(setup)
	var binding, session string
	heartbeat := &cobra.Command{Use: "heartbeat", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		return c.runAutomaticHeartbeat(cmd.Context(), binding, session, 15*time.Second)
	}}
	heartbeat.Flags().StringVar(&binding, "auto", "", "Automatic binding ID")
	heartbeat.Flags().StringVar(&session, "session", "", "Expected session ID")
	heartbeat.MarkFlagRequired("auto")
	heartbeat.MarkFlagRequired("session")
	root.AddCommand(heartbeat)
}
