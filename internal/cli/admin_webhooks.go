package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"devctl.local/devctl/internal/store"
	"github.com/spf13/cobra"
)

type webhookList struct {
	Rules []store.Webhook `json:"rules"`
}

func webhookBody(rule store.Webhook, reason string) map[string]any {
	return map[string]any{"name": rule.Name, "url": rule.URL, "events": rule.Events, "cluster_id": rule.ClusterID, "selector": rule.Selector, "blocking": rule.Blocking, "idempotent": rule.Idempotent, "enabled": rule.Enabled, "timeout_seconds": rule.TimeoutSeconds, "reason": reason}
}
func validateWebhookInput(rule store.Webhook) error {
	rule.ID = "cli-validation"
	if err := store.ValidateWebhook(rule); err != nil {
		return errors.New("provide name, events, valid label filters and a timeout from 5m through 24h; blocking requires only cluster_idle and --idempotent")
	}
	address, err := url.Parse(rule.URL)
	if err != nil || address.Scheme != "https" || address.Host == "" || address.User != nil || address.RawQuery != "" || address.Fragment != "" {
		return errors.New("webhook URL must use HTTPS without credentials, query parameters or a fragment")
	}
	if rule.ClusterID != "" {
		return validateHealthCluster(rule.ClusterID)
	}
	return nil
}
func webhookID(id string) error {
	if !healthClusterID.MatchString(id) {
		return errors.New("valid webhook or delivery ID required")
	}
	return nil
}
func (c *Client) addWebhookCommands(admin *cobra.Command) {
	group := &cobra.Command{Use: "webhooks", Short: "Configure event webhooks and inspect delivery holds"}
	for _, entry := range []struct{ name, path string }{{"list", "/v1/admin/webhooks"}, {"runs", "/v1/admin/webhook-deliveries"}} {
		group.AddCommand(&cobra.Command{Use: entry.name, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			var out any
			if err := c.request(cmd.Context(), "GET", entry.path, nil, "", &out); err != nil {
				return err
			}
			return c.print(out)
		}})
	}
	var rule store.Webhook
	var events, selectors []string
	var timeout time.Duration
	var createReason string
	create := &cobra.Command{Use: "create", Short: "Create an event rule and display its signing secret once", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		reason, err := healthAuditReason(createReason)
		if err != nil {
			return err
		}
		if timeout < 5*time.Minute || timeout > 24*time.Hour || timeout%time.Second != 0 {
			return errors.New("--timeout must be whole seconds from 5m through 24h")
		}
		rule.Events = events
		rule.TimeoutSeconds = int(timeout / time.Second)
		rule.Selector, err = personalSelector(selectors)
		if err != nil {
			return err
		}
		if err = validateWebhookInput(rule); err != nil {
			return err
		}
		var out any
		if err = c.request(cmd.Context(), "POST", "/v1/admin/webhooks", webhookBody(rule, reason), "", &out); err != nil {
			return err
		}
		fmt.Fprintln(c.Err, "Save the one-time signing secret on the approved receiver. New rules are disabled unless --enabled is supplied.")
		return c.print(out)
	}}
	create.Flags().StringVar(&rule.Name, "name", "", "Webhook display name")
	create.Flags().StringVar(&rule.URL, "url", "", "Approved HTTPS receiver URL")
	create.Flags().StringSliceVar(&events, "event", nil, "Event names from admin webhooks list")
	create.Flags().StringVar(&rule.ClusterID, "cluster", "", "Optional exact cluster ID filter")
	create.Flags().StringSliceVar(&selectors, "selector", nil, "Optional equality labels key=value")
	create.Flags().BoolVar(&rule.Blocking, "blocking", false, "Hold a cluster after cluster_idle until callback and health verification")
	create.Flags().BoolVar(&rule.Idempotent, "idempotent", false, "Confirm the receiver deduplicates the delivery Idempotency-Key")
	create.Flags().BoolVar(&rule.Enabled, "enabled", false, "Enable future matching deliveries")
	create.Flags().DurationVar(&timeout, "timeout", time.Hour, "Completion deadline from 5m through 24h")
	create.Flags().StringVar(&createReason, "reason", "", "Required audit reason")
	group.AddCommand(create)
	var file, updateReason string
	var expected int64
	update := &cobra.Command{Use: "update WEBHOOK_ID", Short: "Replace rule configuration from JSON with an expected version", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := webhookID(args[0]); err != nil {
			return err
		}
		reason, err := healthAuditReason(updateReason)
		if err != nil {
			return err
		}
		if file == "" || expected < 1 {
			return errors.New("--file and positive --expected-version are required")
		}
		input, err := os.Open(file)
		if err != nil {
			return errors.New("cannot read webhook configuration file")
		}
		defer input.Close()
		raw, err := io.ReadAll(io.LimitReader(input, 65537))
		if err != nil || len(raw) > 65536 {
			return errors.New("webhook configuration must be at most 64 KiB")
		}
		var value store.Webhook
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&value); err != nil {
			return errors.New("invalid webhook JSON configuration")
		}
		if decoder.Decode(new(any)) != io.EOF {
			return errors.New("provide one webhook JSON object")
		}
		if err = validateWebhookInput(value); err != nil {
			return err
		}
		body := webhookBody(value, reason)
		body["expected_version"] = expected
		var out any
		if err = c.request(cmd.Context(), "PATCH", "/v1/admin/webhooks/"+url.PathEscape(args[0]), body, "", &out); err != nil {
			return err
		}
		return c.print(out)
	}}
	update.Flags().StringVar(&file, "file", "", "Rule JSON file; metadata only, no signing secret")
	update.Flags().Int64Var(&expected, "expected-version", 0, "Current version from admin webhooks list")
	update.Flags().StringVar(&updateReason, "reason", "", "Required audit reason")
	group.AddCommand(update)
	var disableReason string
	disable := &cobra.Command{Use: "disable WEBHOOK_ID", Short: "Stop future matches; queued deliveries and holds remain", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := webhookID(args[0]); err != nil {
			return err
		}
		reason, err := healthAuditReason(disableReason)
		if err != nil {
			return err
		}
		var list webhookList
		if err = c.request(cmd.Context(), "GET", "/v1/admin/webhooks", nil, "", &list); err != nil {
			return err
		}
		for _, current := range list.Rules {
			if current.ID == args[0] {
				current.Enabled = false
				body := webhookBody(current, reason)
				body["expected_version"] = current.Version
				var out any
				if err = c.request(cmd.Context(), "PATCH", "/v1/admin/webhooks/"+url.PathEscape(args[0]), body, "", &out); err != nil {
					return err
				}
				return c.print(out)
			}
		}
		return &ExitError{5, errors.New("webhook not found")}
	}}
	disable.Flags().StringVar(&disableReason, "reason", "", "Required audit reason")
	group.AddCommand(disable)
	for _, name := range []string{"retry", "resolve"} {
		var reason, state string
		var stopped bool
		action := &cobra.Command{Use: name + " DELIVERY_ID", Short: map[string]string{"retry": "Retry the same delivery ID without starting a new execution", "resolve": "Resolve one hold after external work has stopped"}[name], Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			if err := webhookID(args[0]); err != nil {
				return err
			}
			why, err := healthAuditReason(reason)
			if err != nil {
				return err
			}
			if state == "" || name == "resolve" && !stopped {
				return errors.New("--expected-state is required; resolving also requires --confirmed-stopped")
			}
			body := map[string]any{"expected_state": state, "reason": why}
			if name == "resolve" {
				body["confirmed_stopped"] = true
			}
			var out any
			if err = c.request(cmd.Context(), "POST", "/v1/admin/webhook-deliveries/"+url.PathEscape(args[0])+"/"+name, body, "", &out); err != nil {
				return err
			}
			return c.print(out)
		}}
		action.Flags().StringVar(&reason, "reason", "", "Required audit reason")
		action.Flags().StringVar(&state, "expected-state", "", "Current delivery state from admin webhooks runs")
		if name == "resolve" {
			action.Flags().BoolVar(&stopped, "confirmed-stopped", false, "Confirm external work has stopped and the cluster was reviewed")
		}
		group.AddCommand(action)
	}
	admin.AddCommand(group)
}
