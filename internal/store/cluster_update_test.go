package store_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/scheduler"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
)

func labelsUpdate(previous, desired map[string]string) store.ClusterUpdate {
	return store.ClusterUpdate{Labels: &desired, ExpectedLabels: &previous}
}

func TestValidateClusterUpdate(t *testing.T) {
	on := true
	empty := map[string]string{}
	valid := map[string]string{"example.com/team": "platform", "marker": ""}
	for _, patch := range []store.ClusterUpdate{{Maintenance: &on}, labelsUpdate(empty, valid), {Maintenance: &on, Labels: &empty, ExpectedLabels: &valid}} {
		if err := store.ValidateClusterUpdate(patch, " reason "); err != nil {
			t.Fatal("valid update rejected", err)
		}
	}
	many := map[string]string{}
	for i := range 33 {
		many[fmt.Sprintf("label-%d", i)] = "x"
	}
	for _, patch := range []store.ClusterUpdate{
		{}, {ExpectedLabels: &empty}, {Labels: &valid},
		labelsUpdate(empty, map[string]string{"bad key": "test"}),
		labelsUpdate(empty, map[string]string{"key": "a,b"}),
		labelsUpdate(empty, map[string]string{"key": strings.Repeat("v", 64)}),
		labelsUpdate(empty, many),
	} {
		if err := store.ValidateClusterUpdate(patch, "reason"); err == nil {
			t.Fatal("invalid patch accepted")
		}
	}
	for _, reason := range []string{"", " \n\t ", strings.Repeat("x", 1001)} {
		if err := store.ValidateClusterUpdate(labelsUpdate(empty, valid), reason); err == nil {
			t.Fatal("invalid reason accepted")
		}
	}
	// Access checks must precede persistence even when called without the API.
	if err := (&store.Store{}).UpdateCluster(ctx, identity("developer"), "cluster", labelsUpdate(empty, valid), "forged"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("developer metadata edit accepted", err)
	}
}

func TestClusterLabelsPreserveHeldSessionCredentialsAndPAT(t *testing.T) {
	s, dsn := testutil.Database(t)
	original := map[string]string{"region": "eu"}
	changed := map[string]string{"region": "us", "marker": ""}
	registerLabelled(t, s, "a", original)
	u, admin := identity("alice"), adminIdentity()
	held, _, err := s.Book(ctx, u, model.Booking{Cluster: "a"}, "first")
	if err != nil {
		t.Fatal(err)
	}
	pat, raw, err := s.CreatePATWithPolicy(ctx, u, "fixture", time.Hour, model.AutoBookingPolicy{Enabled: true, Selector: original})
	if err != nil {
		t.Fatal(err)
	}
	persistedPAT, err := s.PAT(ctx, u, pat.ID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Profile(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	var encrypted, digest []byte
	if err = s.Pool.QueryRow(ctx, "SELECT kubeconfig_ciphertext FROM clusters WHERE id='a'").Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if err = s.Pool.QueryRow(ctx, "SELECT token_digest FROM personal_access_tokens WHERE id=$1", pat.ID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateCluster(ctx, admin, "a", labelsUpdate(original, changed), "  correct placement metadata  "); err != nil {
		t.Fatal(err)
	}
	after, err := s.Profile(ctx, u)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("metadata edit changed reservation, expiry or primary", err)
	}
	stillPAT, err := s.PAT(ctx, u, pat.ID)
	if err != nil || !reflect.DeepEqual(persistedPAT, stillPAT) {
		t.Fatal("metadata edit changed PAT policy or expiry", err)
	}
	var stillEncrypted, stillDigest []byte
	if err = s.Pool.QueryRow(ctx, "SELECT kubeconfig_ciphertext FROM clusters WHERE id='a'").Scan(&stillEncrypted); err != nil {
		t.Fatal(err)
	}
	if err = s.Pool.QueryRow(ctx, "SELECT token_digest FROM personal_access_tokens WHERE id=$1", pat.ID).Scan(&stillDigest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encrypted, stillEncrypted) || !bytes.Equal(digest, stillDigest) {
		t.Fatal("metadata edit replaced a credential")
	}
	current, version, _, _, err := s.PrimaryPATConfig(ctx, raw)
	if err != nil || current.ID != held.ID || version != before.SelectionVersion {
		t.Fatal("label edit switched an existing primary outside the selector", err)
	}
	if err = s.Stop(ctx, u, held.ID, "exercise future placement", false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err = s.PrimaryPATConfig(ctx, raw); !errors.Is(err, scheduler.ErrUnavailable) {
		t.Fatal("old selector still matched edited metadata", err)
	}
	// Restarting replays schema migrations without restoring old registry labels.
	reopened, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Pool.Close()
	cluster, err := reopened.Cluster(ctx, "a")
	if err != nil || !maps.Equal(cluster.Labels, changed) {
		t.Fatal("edited labels did not survive restart", err)
	}
	if err = reopened.UpdateCluster(ctx, admin, "a", labelsUpdate(changed, original), "restore future match"); err != nil {
		t.Fatal(err)
	}
	next, _, _, _, err := reopened.PrimaryPATConfig(ctx, raw)
	if err != nil || next.Cluster != "a" || next.ID == held.ID {
		t.Fatal("same PAT failed to use later registry label edit", err)
	}
	var actor, detail string
	if err = s.Pool.QueryRow(ctx, "SELECT actor,detail FROM audit WHERE action='cluster_labels_update' AND object_id='a' ORDER BY id LIMIT 1").Scan(&actor, &detail); err != nil {
		t.Fatal(err)
	}
	var audit struct {
		Reason   string            `json:"reason"`
		Previous map[string]string `json:"previous_labels"`
		Labels   map[string]string `json:"labels"`
	}
	if json.Unmarshal([]byte(detail), &audit) != nil || actor != admin.Key() || audit.Reason != "correct placement metadata" || !maps.Equal(audit.Previous, original) || !maps.Equal(audit.Labels, changed) {
		t.Fatal("audited identity/reason/label delta missing")
	}
	if strings.Contains(detail, "encrypted-fixture") || strings.Contains(detail, raw) {
		t.Fatal("label audit exposed credential material")
	}
}

func TestClusterUpdateAtomicConflictClearAndRetirement(t *testing.T) {
	s, _ := testutil.Database(t)
	registerLabelled(t, s, "a", map[string]string{"region": "eu"})
	admin := adminIdentity()
	on := true
	current := map[string]string{"region": "eu"}
	stale := map[string]string{"region": "ap"}
	desired := map[string]string{"region": "us"}
	patch := labelsUpdate(stale, desired)
	patch.Maintenance = &on
	if err := s.UpdateCluster(ctx, admin, "a", patch, "stale combined edit"); !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "reload") {
		t.Fatal("stale edit did not explain conflict", err)
	}
	c, err := s.Cluster(ctx, "a")
	if err != nil || c.Maintenance || !maps.Equal(c.Labels, current) {
		t.Fatal("stale label edit partially changed maintenance", err)
	}
	patch.ExpectedLabels = &current
	if err = s.UpdateCluster(ctx, admin, "a", patch, "combined edit"); err != nil {
		t.Fatal(err)
	}
	c, err = s.Cluster(ctx, "a")
	if err != nil || !c.Maintenance || !maps.Equal(c.Labels, desired) {
		t.Fatal("combined patch was not applied", err)
	}
	empty := map[string]string{}
	if err = s.UpdateCluster(ctx, admin, "a", labelsUpdate(desired, empty), "clear labels"); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateCluster(ctx, admin, "a", labelsUpdate(empty, empty), "unchanged retry"); err != nil {
		t.Fatal(err)
	}
	c, err = s.Cluster(ctx, "a")
	if err != nil || !c.Maintenance || len(c.Labels) != 0 {
		t.Fatal("clearing labels changed omitted placement field", err)
	}
	var count int
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='cluster_labels_update'").Scan(&count); err != nil || count != 2 {
		t.Fatal("no-op edit duplicated success audit", count, err)
	}
	if err = s.UpdateCluster(ctx, admin, "missing", labelsUpdate(empty, desired), "unknown"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unknown entry edited", err)
	}
	// Historic metadata may predate label validation. Its literal snapshot can
	// still be replaced with valid labels rather than becoming impossible to fix.
	if _, err = s.Pool.Exec(ctx, `UPDATE clusters SET labels='{"legacy key":"invalid old value"}'::jsonb WHERE id='a'`); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateCluster(ctx, admin, "a", labelsUpdate(map[string]string{"legacy key": "invalid old value"}, desired), "repair legacy labels"); err != nil {
		t.Fatal(err)
	}
	if err = s.Deregister(ctx, admin, "a", "retire"); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateCluster(ctx, admin, "a", labelsUpdate(desired, empty), "cannot restore"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("label edit revived retired entry", err)
	}
}

func TestConcurrentClusterLabelEditsAcrossStores(t *testing.T) {
	s, dsn := testutil.Database(t)
	other, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Pool.Close()
	original := map[string]string{"region": "original"}
	registerLabelled(t, s, "a", original)
	start := make(chan struct{})
	outcomes := make([]error, 24)
	var wg sync.WaitGroup
	for index := range outcomes {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			service := s
			if index%2 != 0 {
				service = other
			}
			outcomes[index] = service.UpdateCluster(ctx, adminIdentity(), "a", labelsUpdate(original, map[string]string{"region": fmt.Sprintf("edit-%02d", index)}), "concurrent editor")
		}(index)
	}
	close(start)
	wg.Wait()
	successes := 0
	for _, err := range outcomes {
		if err == nil {
			successes++
		} else if !errors.Is(err, store.ErrConflict) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent editors overwrote each other: %d successes", successes)
	}
	var audits int
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='cluster_labels_update'").Scan(&audits); err != nil || audits != 1 {
		t.Fatal("concurrent label edits were not audited once", audits, err)
	}
}

func TestClusterLabelEditsSerializeWithBookingAndDeregistration(t *testing.T) {
	s, dsn := testutil.Database(t)
	other, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Pool.Close()
	for round := range 10 {
		id := fmt.Sprintf("edit-book-%02d", round)
		before, after := map[string]string{"region": "before"}, map[string]string{"region": "after"}
		registerLabelled(t, s, id, before)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var held model.Session
		var bookErr, updateErr error
		u := identity(id)
		go func() {
			defer wg.Done()
			<-start
			held, _, bookErr = s.Book(ctx, u, model.Booking{Cluster: id, Selector: before}, id)
		}()
		go func() {
			defer wg.Done()
			<-start
			updateErr = other.UpdateCluster(ctx, adminIdentity(), id, labelsUpdate(before, after), "placement metadata changed")
		}()
		close(start)
		wg.Wait()
		if updateErr != nil {
			t.Fatal(updateErr)
		}
		if bookErr == nil {
			var bookID, updateID int64
			if err = s.Pool.QueryRow(ctx, "SELECT id FROM audit WHERE action='book' AND object_id=$1", held.ID).Scan(&bookID); err != nil {
				t.Fatal(err)
			}
			if err = s.Pool.QueryRow(ctx, "SELECT id FROM audit WHERE action='cluster_labels_update' AND object_id=$1", id).Scan(&updateID); err != nil || bookID >= updateID {
				t.Fatal("booking matched metadata after it changed", err)
			}
			if err = s.Stop(ctx, u, held.ID, "complete", false); err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(bookErr, scheduler.ErrUnavailable) {
			t.Fatal(bookErr)
		}
		start = make(chan struct{})
		wg.Add(2)
		var retireErr error
		go func() {
			defer wg.Done()
			<-start
			updateErr = s.UpdateCluster(ctx, adminIdentity(), id, labelsUpdate(after, before), "concurrent retirement edit")
		}()
		go func() {
			defer wg.Done()
			<-start
			retireErr = other.Deregister(ctx, adminIdentity(), id, "concurrent retirement")
		}()
		close(start)
		wg.Wait()
		if retireErr != nil || updateErr != nil && !errors.Is(updateErr, store.ErrNotFound) {
			t.Fatal("unsafe edit/retirement result", updateErr, retireErr)
		}
		var archived, credentialRemoved bool
		if err = s.Pool.QueryRow(ctx, "SELECT deregistered_at IS NOT NULL,kubeconfig_ciphertext IS NULL FROM clusters WHERE id=$1", id).Scan(&archived, &credentialRemoved); err != nil || !archived || !credentialRemoved {
			t.Fatal("label edit restored an archived credential", err)
		}
	}
}
