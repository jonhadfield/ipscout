package cache

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
}

// RunGC must be safe on a nil database, since Close is called from deferred
// paths that may run after a failed open.
func TestRunGCNilDB(t *testing.T) {
	t.Parallel()

	require.Equal(t, 0, RunGC(testLogger(), nil, 2))
	require.NoError(t, Close(testLogger(), nil))
}

// A fresh cache has nothing stale, so GC must report no rewrites rather than
// treating badger's ErrNoRewrite as a failure.
func TestRunGCNothingToReclaim(t *testing.T) {
	t.Parallel()

	lg := testLogger()

	db, err := Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)

	require.Equal(t, 0, RunGC(lg, db, 2))

	// rounds <= 0 means "until there is nothing left", which must also terminate.
	require.Equal(t, 0, RunGC(lg, db, 0))

	require.NoError(t, Close(lg, db))
}

// Close must run GC and still close the database, leaving it unusable after.
func TestCloseClosesTheDatabase(t *testing.T) {
	t.Parallel()

	lg := testLogger()

	db, err := Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)

	require.NoError(t, UpsertWithTTL(lg, db, Item{
		Key:     "provider_test",
		Value:   []byte("value"),
		Created: time.Now(),
	}, time.Hour))

	require.NoError(t, Close(lg, db))
	require.True(t, db.IsClosed())
}
