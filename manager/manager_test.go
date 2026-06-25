package manager

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	testItemTTL     = time.Hour
	testItemVersion = "1"
	testAppVersion  = "0.0.1"
	seededItemCount = 3
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
}

// cachePath mirrors the path the manager Client builds internally from HomeDir.
func cachePath(homeDir string) string {
	return filepath.Join(homeDir, ".config", "ipscout")
}

// newTestSession returns a session with a real BadgerDB cache opened at the
// manager's expected path, plus the homeDir used to build it.
func newTestSession(t *testing.T) (*session.Session, string) {
	t.Helper()

	lg := discardLogger()
	homeDir := t.TempDir()

	db, err := cache.Create(lg, cachePath(homeDir))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := &session.Session{
		Logger: lg,
		Stats:  session.CreateStats(),
		Cache:  db,
	}
	sess.Config.Global.HomeDir = homeDir

	return sess, homeDir
}

// seedKey builds a provider-prefixed cache key.
func seedKey(name string) string {
	return providers.CacheProviderPrefix + name
}

// seedItems writes seededItemCount items into the supplied cache.
func seedItems(t *testing.T, db *badger.DB, lg *slog.Logger) []string {
	t.Helper()

	now := time.Now()
	keys := []string{
		seedKey("alpha"),
		seedKey("bravo"),
		seedKey("charlie"),
	}

	for _, k := range keys {
		require.NoError(t, cache.UpsertWithTTL(lg, db, cache.Item{
			Key:        k,
			Value:      []byte(`{"data":"` + k + `"}`),
			Version:    testItemVersion,
			AppVersion: testAppVersion,
			Created:    now,
		}, testItemTTL))
	}

	return keys
}

func TestNewClient(t *testing.T) {
	t.Parallel()

	sess, _ := newTestSession(t)

	c, err := NewClient(sess)
	require.NoError(t, err)
	require.Equal(t, sess, c.Config)
}

func TestGetCacheItemsInfo(t *testing.T) {
	t.Parallel()

	sess, _ := newTestSession(t)
	keys := seedItems(t, sess.Cache, sess.Logger)

	c, err := NewClient(sess)
	require.NoError(t, err)

	info, err := c.GetCacheItemsInfo()
	require.NoError(t, err)
	require.Len(t, info, seededItemCount)

	gotKeys := make(map[string]CacheItemInfo, len(info))
	for _, i := range info {
		gotKeys[i.Key] = i
	}

	for _, k := range keys {
		item, ok := gotKeys[k]
		require.True(t, ok, "expected key %s in cache info", k)
		require.Equal(t, testAppVersion, item.AppVersion)
		require.True(t, item.ExpiresAt.After(time.Now()), "expected future expiry for %s", k)
	}
}

func TestGetCacheItemsInfoEmpty(t *testing.T) {
	t.Parallel()

	sess, _ := newTestSession(t)

	c, err := NewClient(sess)
	require.NoError(t, err)

	info, err := c.GetCacheItemsInfo()
	require.NoError(t, err)
	require.Empty(t, info)
}

func TestCreateItemsInfoTable(t *testing.T) {
	t.Parallel()

	sess, _ := newTestSession(t)
	seedItems(t, sess.Cache, sess.Logger)

	c, err := NewClient(sess)
	require.NoError(t, err)

	info, err := c.GetCacheItemsInfo()
	require.NoError(t, err)

	tw, err := c.CreateItemsInfoTable(info)
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, "CACHE ITEMS")

	for _, i := range info {
		require.Contains(t, rendered, i.Key)
	}
}

func TestCreateItemsInfoTableEmpty(t *testing.T) {
	t.Parallel()

	sess, _ := newTestSession(t)

	c, err := NewClient(sess)
	require.NoError(t, err)

	tw, err := c.CreateItemsInfoTable(nil)
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, "no cache items found")
}

func TestList(t *testing.T) {
	t.Parallel()

	sess, _ := newTestSession(t)
	seedItems(t, sess.Cache, sess.Logger)

	// List opens its own cache from HomeDir, so close the test-held handle
	// first to avoid a concurrent BadgerDB lock on the same directory.
	require.NoError(t, sess.Cache.Close())

	c, err := NewClient(sess)
	require.NoError(t, err)

	require.NoError(t, c.List())
}

func TestGet(t *testing.T) {
	t.Parallel()

	sess, _ := newTestSession(t)
	keys := seedItems(t, sess.Cache, sess.Logger)

	require.NoError(t, sess.Cache.Close())

	c, err := NewClient(sess)
	require.NoError(t, err)

	require.NoError(t, c.Get(keys[0], false))
	require.NoError(t, c.Get(keys[0], true))
}

func TestGetMissingKey(t *testing.T) {
	t.Parallel()

	sess, _ := newTestSession(t)
	require.NoError(t, sess.Cache.Close())

	c, err := NewClient(sess)
	require.NoError(t, err)

	require.Error(t, c.Get(seedKey("does-not-exist"), false))
}

func TestDelete(t *testing.T) {
	t.Parallel()

	sess, homeDir := newTestSession(t)
	keys := seedItems(t, sess.Cache, sess.Logger)

	require.NoError(t, sess.Cache.Close())

	c, err := NewClient(sess)
	require.NoError(t, err)

	require.NoError(t, c.Delete([]string{keys[0]}))

	// Re-open the cache and confirm the deleted key is gone while others remain.
	db, err := cache.Create(sess.Logger, cachePath(homeDir))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	exists, err := cache.CheckExists(sess.Logger, db, keys[0])
	require.NoError(t, err)
	require.False(t, exists)

	exists, err = cache.CheckExists(sess.Logger, db, keys[1])
	require.NoError(t, err)
	require.True(t, exists)
}
