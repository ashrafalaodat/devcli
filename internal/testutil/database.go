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
