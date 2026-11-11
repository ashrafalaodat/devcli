package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"devctl.local/devctl/internal/model"
	"github.com/spf13/cobra"
)

// NewPluginCommand exposes only the commands needed to connect kubectl to a
// reservation. It uses exactly the same login store, PKCE flow, refresh-token
// rotation and automatic access renewal as the full CLI.
func NewPluginCommand() *cobra.Command {
	c := &Client{HTTP: &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Out: os.Stdout, Err: os.Stderr}
	return newPluginCommand(c)
}

func newPluginCommand(c *Client) *cobra.Command {
	root := newCommand(c)
	root.Use = "kubectl devctl"
	root.Short = "Connect kubectl to a reserved cluster through the devctl gateway"
	root.Long = "A small kubectl access plugin. Login, automatic booking and token refresh use the devctl gateway; use the full devctl CLI or web UI for reservation and administrator controls."
	root.CompletionOptions.DisableDefaultCmd = true
	// Commands are removed, rather than merely hidden, so the plugin cannot be
	// used as an alternate entry point for full CLI or administrator operations.
	for _, command := range root.Commands() {
		switch command.Name() {
		case "setup", "logout", "credential", "heartbeat", "shell":
			command.Hidden = command.Name() == "credential" || command.Name() == "heartbeat" || command.Name() == "shell"
		default:
			root.RemoveCommand(command)
		}
	}
	var cluster, ttl string
	var selectors []string
	var reset bool
	login := &cobra.Command{Use: "login", Short: "Log in, book or reuse a cluster, and print the gateway kubeconfig path", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		labels, err := labelMap(selectors)
		if err != nil {
			return err
		}
		replace := cmd.Flags().Changed("cluster") || cmd.Flags().Changed("selector") || cmd.Flags().Changed("ttl")
		booking := model.Booking{Cluster: cluster, Selector: labels, TTL: ttl}
		return c.pluginLogin(cmd.Context(), booking, reset, replace)
	}}
	login.Flags().StringVar(&cluster, "cluster", "", "Cluster ID/name; omitted selects automatically")
	login.Flags().StringSliceVarP(&selectors, "selector", "l", nil, "Required cluster labels")
	login.Flags().StringVar(&ttl, "ttl", "", "Optional booking expiry from 1m through 168h")
	login.Flags().BoolVar(&reset, "new-booking", false, "Explicitly reactivate with a fresh automatic binding")
	root.AddCommand(login)
	root.AddCommand(&cobra.Command{Use: "status", Short: "Show this profile's automatic booking", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		state, err := c.readAutomaticState()
		if err != nil {
			return fmt.Errorf("no readable automatic selection; run kubectl devctl login: %w", err)
		}
		var access automaticAccess
		if err = c.request(cmd.Context(), "GET", c.automaticPath(state.Binding), nil, "", &access); err != nil {
			return err
		}
		return c.print(access.Session)
	}})
	return root
}

func (c *Client) pluginLogin(ctx context.Context, booking model.Booking, reset, replace bool) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	path, err := c.setupAutomatic(ctx, booking, reset, replace)
	if err != nil {
		return err
	}
	// Reuse and refresh an existing login, opening SSO only when required. The
	// credential path below validates ownership and approval before booking.
	token, err := c.automaticToken(ctx, true, "")
	if err != nil {
		return err
	}
	var identity model.Identity
	err = c.withToken(ctx, token.AccessToken, "GET", "/v1/whoami", nil, "", &identity)
	var status *apiStatusError
	if errors.As(err, &status) && status.Status == http.StatusUnauthorized {
		token, err = c.automaticToken(ctx, true, token.AccessToken)
		if err == nil {
			err = c.withToken(ctx, token.AccessToken, "GET", "/v1/whoami", nil, "", &identity)
		}
	}
	if err != nil {
		return err
	}
	state, err := c.readAutomaticState()
	if err != nil {
		return err
	}
	// ExecCredential contains a bearer token and is only for kubectl. Login prints
	// a path, never that token or the refresh token, even with --json.
	out := c.Out
	c.Out = io.Discard
	err = c.automaticCredential(ctx, state.Binding)
	c.Out = out
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Err, "Gateway access selected. Set KUBECONFIG to the printed path, or use the installer's optional shell integration.")
	_, err = fmt.Fprintln(c.Out, path)
	return err
}
