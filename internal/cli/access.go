package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"github.com/gofrs/flock"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

// A detached worker maintains fresh SSO authorization only while genuine
// activity is recent. It never records booking activity or extends inactivity
// deadlines itself; the administrator's inactivity grace is a separate policy.
const accessIdleLimit = 2 * time.Minute

type developerProfile struct {
	OwnerID             string         `json:"owner_id"`
	User                model.Identity `json:"user"`
	MaxBookings         int            `json:"max_bookings"`
	MaxBookingsOverride *int           `json:"max_bookings_override,omitempty"`
	ActiveBookings      int            `json:"active_bookings"`
	PrimarySession      *model.Session `json:"primary_session,omitempty"`
	SelectionVersion    int64          `json:"selection_version"`
}
type primaryAccess struct {
	Session                model.Session `json:"session"`
	SelectionVersion       int64         `json:"selection_version"`
	AuthorizationExpiresAt time.Time     `json:"authorization_expires_at"`
}

// Setup is offline. Login, booking and primary selection are separate operations.
func (c *Client) setupGateway(ctx context.Context) (string, error) {
	var ca []byte
	if c.APICAFile != "" {
		file, err := os.Open(c.APICAFile)
		if err != nil {
			return "", errors.New("cannot read public gateway CA")
		}
		raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		file.Close()
		if err != nil || len(raw) > 1<<20 {
			return "", errors.New("public gateway CA must be at most 1 MiB")
		}
		ca, err = kube.PublicCertificates(raw)
		if err != nil {
			return "", err
		}
	}
	return c.writeGatewayConfig(ctx, Connection{Server: strings.TrimSuffix(c.URL, "/") + "/k8s", CertificateAuthorityData: base64CA(ca)})
}

func base64CA(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

func credentialInteractive() bool {
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

func (c *Client) loginToken(ctx context.Context, interactive bool, rejected string) (*oauth2.Token, error) {
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

func (c *Client) authenticatedProfile(ctx context.Context, interactive bool) (*oauth2.Token, developerProfile, error) {
	var profile developerProfile
	token, err := c.loginToken(ctx, interactive, "")
	if err != nil {
		return nil, profile, err
	}
	err = c.withToken(ctx, token.AccessToken, "GET", "/v1/profile", nil, "", &profile)
	var status *apiStatusError
	if errors.As(err, &status) && status.Status == http.StatusUnauthorized {
		token, err = c.loginToken(ctx, interactive, token.AccessToken)
		if err == nil {
			err = c.withToken(ctx, token.AccessToken, "GET", "/v1/profile", nil, "", &profile)
		}
	}
	if err != nil {
		return nil, profile, err
	}
	if profile.OwnerID == "" || profile.OwnerID != profile.User.Key() {
		return nil, profile, errors.New("backend returned an invalid developer identity")
	}
	return token, profile, nil
}

func (c *Client) credential(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	token, profile, err := c.authenticatedProfile(ctx, credentialInteractive())
	if err != nil {
		return err
	}
	if token.AccessToken == "" || token.Expiry.IsZero() || !token.Expiry.After(time.Now()) {
		return &ExitError{3, errors.New("login has no valid token expiry; run devctl login")}
	}
	if profile.PrimarySession != nil && profile.PrimarySession.State == "ACTIVE" {
		if err = c.startPrimaryHeartbeat(profile.OwnerID, profile.PrimarySession.ID, profile.SelectionVersion); err != nil {
			return fmt.Errorf("could not start authentication renewal worker: %w", err)
		}
	}
	// With no primary booking, still provide valid authentication. The gateway
	// returns its explicit 'no cluster is booked' Kubernetes Status response.
	return json.NewEncoder(c.Out).Encode(map[string]any{"apiVersion": "client.authentication.k8s.io/v1", "kind": "ExecCredential", "status": map[string]string{"token": token.AccessToken, "expirationTimestamp": token.Expiry.UTC().Format(time.RFC3339Nano)}})
}

func (c *Client) heartbeatLock(owner, session string, version int64) *flock.Flock {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d", owner, session, version)))
	return flock.New(filepath.Join(c.Login.Dir, "heartbeat-"+hex.EncodeToString(sum[:16])+".lock"))
}

func (c *Client) startPrimaryHeartbeat(owner, session string, version int64) error {
	lock := c.heartbeatLock(owner, session, version)
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
	command := exec.Command(executable, "--api", c.URL, "heartbeat", "--owner", owner, "--session", session, "--version", fmt.Sprint(version))
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
	configureBackgroundProcess(command)
	if err = command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

func (c *Client) runPrimaryHeartbeat(ctx context.Context, owner, session string, version int64, interval time.Duration) error {
	if len(owner) != 64 || !sessionID.MatchString(session) || version < 1 {
		return errors.New("invalid primary heartbeat identity")
	}
	lock := c.heartbeatLock(owner, session, version)
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
		token, err := c.Login.token(ctx)
		if err != nil {
			return nil
		}
		var access primaryAccess
		if err = c.withToken(ctx, token.AccessToken, "GET", "/v1/access", nil, "", &access); err != nil {
			return nil
		}
		if access.Session.ID != session || access.Session.Owner != owner || access.SelectionVersion != version || access.Session.State != "ACTIVE" || access.Session.LastActivityAt == nil || time.Since(*access.Session.LastActivityAt) > accessIdleLimit {
			return nil
		}
		// Refresh gateway authorization for existing streams, not human presence.
		if err = c.withToken(ctx, token.AccessToken, "POST", "/v1/access/heartbeat", nil, "", &access); err != nil {
			return nil
		}
	}
}

func (c *Client) addAccessCommands(root *cobra.Command) {
	root.AddCommand(&cobra.Command{Use: "setup", Short: "Write your stable gateway kubeconfig without booking a cluster", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		path, err := c.setupGateway(cmd.Context())
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(c.Out, path)
		return err
	}})
	var owner, session string
	var version int64
	heartbeat := &cobra.Command{Use: "heartbeat", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		return c.runPrimaryHeartbeat(cmd.Context(), owner, session, version, 15*time.Second)
	}}
	heartbeat.Flags().StringVar(&owner, "owner", "", "Expected developer identity")
	heartbeat.Flags().StringVar(&session, "session", "", "Expected primary booking")
	heartbeat.Flags().Int64Var(&version, "version", 0, "Expected primary selection version")
	_ = heartbeat.MarkFlagRequired("owner")
	_ = heartbeat.MarkFlagRequired("session")
	_ = heartbeat.MarkFlagRequired("version")
	root.AddCommand(heartbeat)
}
