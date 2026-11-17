package testutil

import (
	"context"
	"devctl.local/devctl/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/url"
	"os"
	"testing"
)

// Each test uses a disposable schema, never truncating application tables.
func Database(t *testing.T) (*store.Store, string) {
	t.Helper()
	dsn := os.Getenv("DEVCTL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set DEVCTL_TEST_DATABASE_URL for PostgreSQL-backed tests")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	schema := "devctl_test_" + uuid.NewString()
	name := pgx.Identifier{schema}.Sanitize()
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+name); e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	testDSN := u.String()
	s, e := store.Open(ctx, testDSN)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Pool.Close(); admin.Exec(ctx, "DROP SCHEMA "+name+" CASCADE"); admin.Close() })
	return s, testDSN
}

// MarkHealthy isolates reservation/transport tests from the health protocol.
// This only seeds owned test schemas; production has no health bypass. Tests of
// monitoring itself use real probes and never call this fixture helper.
func MarkHealthy(t *testing.T, s *store.Store, id string) {
	t.Helper()
	if _, err := s.Pool.Exec(t.Context(), `UPDATE cluster_health h SET observed_state='PASSING',reason_code='checks_passed',
 result='{"passed":true,"reason_code":"checks_passed","readiness_confirmed":true,"discovery_coverage":"baseline","components":[]}'::jsonb,
 observed_configuration_generation=c.configuration_generation,observed_policy_revision=c.health_policy_revision,
 checked_at=clock_timestamp(),last_success_at=clock_timestamp(),consecutive_successes=2,
 next_check_at=clock_timestamp()+interval '1 day',lease_token=NULL,lease_until=NULL,probe_sequence=probe_sequence+1
 FROM clusters c WHERE c.id=h.cluster_id AND c.id=$1`, id); err != nil {
		t.Fatal(err)
	}
}
