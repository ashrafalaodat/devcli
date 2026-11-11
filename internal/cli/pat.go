package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"

	"devctl.local/devctl/internal/store"
	"github.com/spf13/cobra"
)

var personalTokenID = regexp.MustCompile(`^p-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// Credential response bodies and cleanup errors may themselves be sensitive.
// Report only a local, fixed message while preserving useful CLI exit codes.
func personalIssuanceError(err error) error {
	message := errors.New("cannot issue personal gateway credential; check your login and requested duration")
	var exit *ExitError
	if errors.As(err, &exit) {
		return &ExitError{Code: exit.Code, Err: message}
	}
	return message
}

func (c *Client) personalFileError(ctx context.Context, id, message string) error {
	if err := c.request(ctx, "DELETE", "/v1/pats/"+url.PathEscape(id), nil, "", nil); err != nil {
		return fmt.Errorf("%s; could not revoke issued PAT %s; revoke it through the web UI or devctl token revoke", message, id)
	}
	return errors.New(message + "; issued PAT was revoked")
}

func (c *Client) addPATCommands(root *cobra.Command) {
	token := &cobra.Command{Use: "token", Short: "Manage personal gateway credentials (separate from SSO login)"}
	token.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		var out []store.PAT
		if err := c.request(cmd.Context(), "GET", "/v1/pats", nil, "", &out); err != nil {
			return err
		}
		return c.print(out)
	}})
	var name, ttl, output string
	create := &cobra.Command{Use: "create", Short: "Write a one-time PAT kubeconfig and print only its path", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		var result struct {
			PAT        store.PAT `json:"pat"`
			Kubeconfig string    `json:"kubeconfig"`
		}
		if err := c.request(cmd.Context(), "POST", "/v1/pats", map[string]string{"name": name, "ttl": ttl}, "", &result); err != nil {
			return personalIssuanceError(err)
		}
		if !personalTokenID.MatchString(result.PAT.ID) {
			return errors.New("invalid personal credential response; no file was written; check the web UI for issued credentials")
		}
		path := output
		if path == "" {
			path = filepath.Join(c.Login.Dir, result.PAT.ID+".yaml")
		}
		path, err := filepath.Abs(path)
		if err != nil {
			return c.personalFileError(cmd.Context(), result.PAT.ID, "cannot resolve credential output path")
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return c.personalFileError(cmd.Context(), result.PAT.ID, "cannot create new credential file (existing files are never overwritten)")
		}
		_, writeErr := f.WriteString(result.Kubeconfig)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			_ = os.Remove(path)
			return c.personalFileError(cmd.Context(), result.PAT.ID, "cannot write credential file")
		}
		fmt.Fprintf(c.Err, "Personal gateway credential %s expires %s. Store this file privately; it cannot refresh itself.\n", result.PAT.ID, result.PAT.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"))
		_, err = fmt.Fprintln(c.Out, path)
		return err
	}}
	create.Flags().StringVar(&name, "name", "CLI personal credential", "Credential display name")
	create.Flags().StringVar(&ttl, "ttl", "8h", "Credential duration, from 1m through 168h")
	create.Flags().StringVar(&output, "output", "", "New private output file (default: profile directory)")
	token.AddCommand(create)
	var reason string
	revoke := &cobra.Command{Use: "revoke PAT_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var out any
		if err := c.request(cmd.Context(), "DELETE", "/v1/pats/"+url.PathEscape(args[0]), map[string]string{"reason": reason}, "", &out); err != nil {
			return err
		}
		return c.print(out)
	}}
	revoke.Flags().StringVar(&reason, "reason", "", "Audit reason (required when revoking another user's PAT as administrator)")
	token.AddCommand(revoke)
	root.AddCommand(token)
}
