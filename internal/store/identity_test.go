package store_test

import (
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
	"errors"
	"testing"
)

func TestSessionOwnershipUsesIssuerAndSubject(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	owner := identity("alice")
	owner.Subject = "original-alice-subject"
	session, _, err := s.Book(ctx, owner, model.Booking{Cluster: "a"}, "owner-booking")
	if err != nil {
		t.Fatal(err)
	}
	if cluster, encrypted, err := s.Config(ctx, owner, session.ID); err != nil || cluster != "a" || len(encrypted) == 0 {
		t.Fatalf("owner cannot access registered credentials: cluster=%q, err=%v", cluster, err)
	}

	recreatedUser := owner
	recreatedUser.Subject = "recreated-alice-subject"
	otherIssuer := owner
	otherIssuer.Issuer = "https://another-issuer.test"
	for _, test := range []struct {
		name string
		user model.Identity
	}{
		{"same_name_and_email_new_subject", recreatedUser},
		{"same_name_email_and_subject_other_issuer", otherIssuer},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, operation := range []struct {
				name string
				run  func() error
			}{
				{"stop", func() error { return s.Stop(ctx, test.user, session.ID, "unauthorized stop", false) }},
				{"force_stop_without_admin", func() error { return s.Stop(ctx, test.user, session.ID, "unauthorized force", true) }},
				{"share", func() error { return s.Share(ctx, test.user, session.ID, true) }},
				{"primary", func() error { _, err := s.SelectPrimary(ctx, test.user, session.ID); return err }},
				{"access", func() error { return s.Access(ctx, test.user, session.ID) }},
			} {
				t.Run(operation.name, func(t *testing.T) {
					if err := operation.run(); !errors.Is(err, store.ErrForbidden) {
						t.Fatalf("expected ownership rejection, got %v", err)
					}
				})
			}
			if _, encrypted, err := s.Config(ctx, test.user, session.ID); !errors.Is(err, store.ErrForbidden) || len(encrypted) != 0 {
				t.Fatalf("another identity obtained credentials or wrong rejection: err=%v", err)
			}
		})
	}

	clusters, sessions, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].State != "ACTIVE" || sessions[0].Owner != owner.Key() ||
		sessions[0].ExpiresAt == nil || !sessions[0].ExpiresAt.Equal(*session.ExpiresAt) {
		t.Fatal("rejected operations changed the owner's reservation")
	}
	if len(clusters) != 1 || clusters[0].Shareable || clusters[0].Available || clusters[0].ControllerSession != session.ID {
		t.Fatal("rejected operations changed cluster ownership or sharing")
	}

	admin := identity("admin")
	admin.Admin = true
	if err := s.Stop(ctx, admin, session.ID, "ordinary stop", false); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("ordinary stop bypassed ownership for an administrator: %v", err)
	}
	const reason = "Release orphaned booking after local identity provider recreation"
	if err := s.Stop(ctx, admin, session.ID, reason, true); err != nil {
		t.Fatal(err)
	}
	clusters, sessions, err = s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].State != "RELEASED" || sessions[0].Owner != owner.Key() ||
		sessions[0].EndedAt == nil || sessions[0].Reason != reason {
		t.Fatal("administrator release did not retain ownership and record release details")
	}
	if len(clusters) != 1 || !clusters[0].Available || clusters[0].ControllerSession != "" {
		t.Fatal("administrator release did not free the reservation")
	}
	if err := s.Access(ctx, owner, session.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("released booking still allows access: %v", err)
	}
	var actor, detail string
	if err := s.Pool.QueryRow(ctx, "SELECT actor,detail FROM audit WHERE action='release' AND object_id=$1", session.ID).Scan(&actor, &detail); err != nil {
		t.Fatal(err)
	}
	if actor != admin.Key() || detail != reason {
		t.Fatal("administrator release audit lacks the administrator identity or reason")
	}
}
