package cli

import (
	"fmt"
	"text/tabwriter"
	"time"

	"devctl.local/devctl/internal/model"
)

func (c *Client) printSessionTable(sessions []model.Session) error {
	w := tabwriter.NewWriter(c.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SESSION\tCLUSTER\tPRIMARY\tDEVELOPER\tCONTACT\tSTATE\tLAST ACTIVITY\tAUTO-RELEASE (INACTIVE)")
	for _, session := range sessions {
		activity, release := "—", "—"
		if session.LastActivityAt != nil {
			activity = session.LastActivityAt.UTC().Format(time.RFC3339)
		}
		if session.ExpiresAt != nil {
			release = session.ExpiresAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%t\t%s\t%s\t%s\t%s\t%s\n", session.ID, session.Cluster, session.Primary, session.DisplayName, session.Email, session.State, activity, release)
	}
	return w.Flush()
}

func (c *Client) printProfile(profile developerProfile) error {
	if c.JSON {
		return c.print(profile)
	}
	if _, err := fmt.Fprintf(c.Out, "Active bookings: %d of %d\n", profile.ActiveBookings, profile.MaxBookings); err != nil {
		return err
	}
	if profile.PrimarySession == nil {
		_, err := fmt.Fprintln(c.Out, "No cluster is booked as primary.")
		return err
	}
	return c.printSessionTable([]model.Session{*profile.PrimarySession})
}
