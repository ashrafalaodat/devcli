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

func TestFullClusterUpdateValidationAndAdministrativeReads(t *testing.T) {
	name, maximum, version := "renamed", 4, int64(1)
	profile := model.HealthProfileDiscoveryOnly
	valid := store.ClusterUpdate{Name: &name, MaxParticipants: &maximum, HealthProfile: &profile, ExpectedVersion: &version, Ciphertext: []byte("encrypted-new")}
	if err := store.ValidateClusterUpdate(valid, "update connection"); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*store.ClusterUpdate){
		func(p *store.ClusterUpdate) { p.ExpectedVersion = nil },
		func(p *store.ClusterUpdate) { v := int64(0); p.ExpectedVersion = &v },
		func(p *store.ClusterUpdate) { v := " "; p.Name = &v },
		func(p *store.ClusterUpdate) { v := strings.Repeat("x", 129); p.Name = &v },
		func(p *store.ClusterUpdate) { v := 1; p.MaxParticipants = &v },
		func(p *store.ClusterUpdate) { v := 11; p.MaxParticipants = &v },
		func(p *store.ClusterUpdate) { v := model.HealthProfile("unknown"); p.HealthProfile = &v },
		func(p *store.ClusterUpdate) { p.Ciphertext = []byte{} },
	} {
		invalid := valid
		change(&invalid)
		if err := store.ValidateClusterUpdate(invalid, "update connection"); err == nil {
			t.Fatal("invalid full edit accepted")
		}
	}
	unauthenticated := &store.Store{}
	if _, err := unauthenticated.AdminCluster(ctx, identity("alice"), "a"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("developer could read administrator editor", err)
	}
	if _, err := unauthenticated.AdminKubeconfig(ctx, identity("alice"), "a", "view"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("developer could read encrypted administrator credential", err)
	}
}

func TestFullClusterUpdateFencesConfigurationAndStaleEditors(t *testing.T) {
	s, dsn := testutil.Database(t)
	register(t, s, "a")
	register(t, s, "b")
	admin := adminIdentity()
	before, err := s.AdminCluster(ctx, admin, "a")
	if err != nil || before.RegistryVersion != 1 || !before.Available {
		t.Fatal("initial editor snapshot invalid", before, err)
	}
	// A fresh health result does not invalidate a registration-editing snapshot.
	testutil.MarkHealthy(t, s, "a")
	if _, err = s.Pool.Exec(ctx, "UPDATE cluster_health SET next_check_at=clock_timestamp() WHERE cluster_id='a'"); err != nil {
		t.Fatal(err)
	}
	claims, err := s.ClaimHealthChecks(ctx, 4)
	if err != nil || len(claims) != 1 || claims[0].ClusterID != "a" {
		t.Fatal("could not claim in-flight old configuration probe", len(claims), err)
	}
	name, maximum, paused := "A renamed", 4, true
	profile := model.HealthProfileDiscoveryOnly
	labels := map[string]string{"region": "eu"}
	patch := store.ClusterUpdate{Name: &name, Labels: &labels, Maintenance: &paused, MaxParticipants: &maximum, HealthProfile: &profile, Ciphertext: []byte("new-encrypted-credential"), ExpectedVersion: &before.RegistryVersion}
	if err = s.UpdateCluster(ctx, admin, "a", patch, "rotate approved credentials"); err != nil {
		t.Fatal(err)
	}
	after, err := s.AdminCluster(ctx, admin, "a")
	if err != nil || after.Name != name || after.MaxParticipants != maximum || !after.Maintenance || !maps.Equal(after.Labels, labels) || after.HealthProfile != profile || after.RegistryVersion != before.RegistryVersion+1 {
		t.Fatal("full edit was not one atomic registry revision", after, err)
	}
	if after.ConfigurationGeneration != before.ConfigurationGeneration+1 || after.HealthPolicyRevision != before.HealthPolicyRevision+1 || after.Health.State != "UNKNOWN" || after.Health.CheckedAt != nil {
		t.Fatal("new connection retained an old health result", after.Health)
	}
	if published, err := s.PublishHealthCheck(ctx, claims[0], model.HealthResult{Passed: true, ReasonCode: "checks_passed"}, time.Minute); err != nil || published {
		t.Fatal("old configuration probe overwrote new connection state", published, err)
	}
	if err = s.UpdateCluster(ctx, admin, "a", patch, "stale editor"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("stale full edit overwrote current registration", err)
	}
	config, err := s.AdminKubeconfig(ctx, admin, "a", "investigate approved connection")
	if err != nil || config.RegistryVersion != after.RegistryVersion || !bytes.Equal(config.Ciphertext, patch.Ciphertext) {
		t.Fatal("audited editor loaded a different credential revision", err)
	}
	encoded, err := json.Marshal(config)
	if err != nil || strings.Contains(string(encoded), "credential") {
		t.Fatal("store credential wrapper exposed ciphertext through JSON", err)
	}
	if _, err = s.AdminKubeconfig(ctx, admin, "a", " "); !errors.Is(err, store.ErrConflict) {
		t.Fatal("credential reveal accepted without audit reason", err)
	}
	var exposed bool
	if err = s.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM audit WHERE detail LIKE '%new-encrypted-credential%')").Scan(&exposed); err != nil || exposed {
		t.Fatal("audit exposed credential contents", err)
	}
	var viewed int
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='cluster_kubeconfig_view' AND actor=$1 AND object_id='a'", admin.Key()).Scan(&viewed); err != nil || viewed != 1 {
		t.Fatal("administrative credential view missing audit", viewed, err)
	}
	duplicate := "b"
	if err = s.UpdateCluster(ctx, admin, "a", store.ClusterUpdate{Name: &duplicate, ExpectedVersion: &after.RegistryVersion}, "duplicate display name"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("duplicate name did not return a safe conflict", err)
	}
	reopened, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Pool.Close()
	persisted, err := reopened.AdminCluster(ctx, admin, "a")
	if err != nil || persisted.RegistryVersion != after.RegistryVersion || persisted.Name != name {
		t.Fatal("restart changed registration version or edited fields", err)
	}
	if err = s.Deregister(ctx, admin, "a", "retire edited registration"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AdminCluster(ctx, admin, "a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("retired registration still editable", err)
	}
	if _, err = s.AdminKubeconfig(ctx, admin, "a", "view retired credential"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("retired credential still readable", err)
	}
}

func TestClusterSharingLimitPreservesHoldersAndVersionedConcurrentEditors(t *testing.T) {
	s, dsn := testutil.Database(t)
	register(t, s, "a")
	admin := adminIdentity()
	cluster, err := s.AdminCluster(ctx, admin, "a")
	if err != nil {
		t.Fatal(err)
	}
	maximum := 3
	if err = s.UpdateCluster(ctx, admin, "a", store.ClusterUpdate{MaxParticipants: &maximum, ExpectedVersion: &cluster.RegistryVersion}, "support three approved holders"); err != nil {
		t.Fatal(err)
	}
	alice := identity("alice")
	first, _, err := s.Book(ctx, alice, model.Booking{Cluster: "a"}, "a")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Share(ctx, alice, first.ID, true); err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"bob", "charlie"} {
		if _, _, err = s.Book(ctx, identity(user), model.Booking{Cluster: "a"}, user); err != nil {
			t.Fatal(err)
		}
	}
	cluster, err = s.AdminCluster(ctx, admin, "a")
	if err != nil || cluster.RegistryVersion != 2 || len(cluster.Participants) != 3 {
		t.Fatal("holder changes invalidated administrator snapshot", cluster, err)
	}
	maximum = 2
	if err = s.UpdateCluster(ctx, admin, "a", store.ClusterUpdate{MaxParticipants: &maximum, ExpectedVersion: &cluster.RegistryVersion}, "unsafe lowering"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("sharing limit lowered below active holders", err)
	}
	other, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Pool.Close()
	start := make(chan struct{})
	outcomes := make([]error, 12)
	var wg sync.WaitGroup
	for i := range outcomes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			name := fmt.Sprintf("name-%02d", i)
			service := s
			if i%2 == 1 {
				service = other
			}
			outcomes[i] = service.UpdateCluster(ctx, admin, "a", store.ClusterUpdate{Name: &name, ExpectedVersion: &cluster.RegistryVersion}, "concurrent full editor")
		}(i)
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
		t.Fatal("full editors overwrote each other", successes)
	}
	current, err := s.AdminCluster(ctx, admin, "a")
	if err != nil || len(current.Participants) != 3 || current.RegistryVersion != cluster.RegistryVersion+1 || current.MaxParticipants != 3 {
		t.Fatal("metadata edit disturbed holders or accepted unsafe limit", current, err)
	}
}

func TestAdministrativeRegistryActionsDoNotChangeDeveloperActivity(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	u, admin := identity("alice"), adminIdentity()
	held, _, err := s.Book(ctx, u, model.Booking{Cluster: "a"}, "held")
	if err != nil {
		t.Fatal(err)
	}
	pat, _, err := s.CreatePAT(ctx, u, "fixture", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Even if a reservation is due for the expiry worker, viewing or editing
	// registry configuration must not masquerade as developer activity/cleanup.
	if _, err = s.Pool.Exec(ctx, "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", held.ID); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		t.Helper()
		var out string
		if err := s.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
 'session',(SELECT to_jsonb(s) FROM sessions s WHERE id=$1),
 'developer',(SELECT to_jsonb(d) FROM developers d WHERE owner_id=$2),
 'pat',(SELECT to_jsonb(p) FROM personal_access_tokens p WHERE id=$3))::text`, held.ID, u.Key(), pat.ID).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := snapshot()
	cluster, err := s.AdminCluster(ctx, admin, "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AdminKubeconfig(ctx, admin, "a", "inspect approved connection"); err != nil {
		t.Fatal(err)
	}
	name := "A renamed"
	if err = s.UpdateCluster(ctx, admin, "a", store.ClusterUpdate{Name: &name, Ciphertext: []byte("new-encrypted-fixture"), ExpectedVersion: &cluster.RegistryVersion}, "rotate registry connection"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AdminCluster(ctx, admin, "a"); err != nil {
		t.Fatal(err)
	}
	if snapshot() != before {
		t.Fatal("administrator registry actions changed developer activity, expiry, reservation, primary or PAT state")
	}
}
