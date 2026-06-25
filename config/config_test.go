package config

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	testIndentSpaces  = 2
	testMaxValueChars = 100
	testMaxReports    = 5
)

// newTestSession builds a session backed by a temporary BadgerDB cache so the
// config client logic runs without touching real $HOME config or the network.
func newTestSession(t *testing.T) *session.Session {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	homeDir := t.TempDir()

	db, err := cache.Create(lg, filepath.Join(homeDir, ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := &session.Session{
		Logger: lg,
		Stats:  session.CreateStats(),
		Cache:  db,
	}

	sess.Config.Global.HomeDir = homeDir
	sess.Config.Global.IndentSpaces = testIndentSpaces
	sess.Config.Global.MaxValueChars = testMaxValueChars
	sess.Config.Global.MaxAge = "90d"
	sess.Config.Global.MaxReports = testMaxReports
	sess.Config.Rating.ConfigPath = "/some/path"
	sess.Config.Rating.UseAI = true

	enabled := true
	disabled := false
	sess.Providers.AbuseIPDB.Enabled = &enabled
	sess.Providers.Annotated.Enabled = &enabled
	sess.Providers.Annotated.Paths = []string{"/a/path", "/b/path"}
	sess.Providers.IPURL.Enabled = &disabled
	sess.Providers.IPURL.URLs = []string{"https://example.com/list"}

	return sess
}

func TestNewClient(t *testing.T) {
	t.Parallel()

	sess := &session.Session{}

	c, err := NewClient(sess)
	require.NoError(t, err)
	require.Same(t, sess, c.Sess)
}

func TestCreateConfigTable(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)

	c := &Client{Sess: sess}

	tw, err := c.CreateConfigTable()
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, "CONFIG")
	require.Contains(t, rendered, "Global")
	require.Contains(t, rendered, "Providers")
	require.Contains(t, rendered, "AbuseIPDB")
}

func TestCreateConfigTableOpenAIKeyDefined(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)
	sess.Config.Rating.OpenAIAPIKey = "sk-test"

	c := &Client{Sess: sess}

	tw, err := c.CreateConfigTable()
	require.NoError(t, err)

	rendered := (*tw).Render()
	require.Contains(t, rendered, "<defined>")
	require.NotContains(t, rendered, "<not defined>")
}

func TestCreateConfigTableOpenAIKeyUndefined(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)

	c := &Client{Sess: sess}

	tw, err := c.CreateConfigTable()
	require.NoError(t, err)

	rendered := (*tw).Render()
	require.Contains(t, rendered, "<not defined>")
}

func TestShow(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)

	c := &Client{Sess: sess}

	require.NoError(t, c.Show())
}

func TestGetCacheItemsInfoEmpty(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)

	c := &Client{Sess: sess}

	items, err := c.GetCacheItemsInfo()
	require.NoError(t, err)
	require.Empty(t, items)
}

func TestGetCacheItemsInfoWithItems(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)

	key := providers.CacheProviderPrefix + "shodan_8.8.8.8"

	err := cache.UpsertWithTTL(sess.Logger, sess.Cache, cache.Item{
		Key:        key,
		Value:      []byte(`{"data":"test"}`),
		AppVersion: "1.2.3",
		Created:    time.Now(),
	}, time.Hour)
	require.NoError(t, err)

	c := &Client{Sess: sess}

	items, err := c.GetCacheItemsInfo()
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, key, items[0].Key)
	require.Equal(t, "1.2.3", items[0].AppVersion)
}

func TestGetCacheItemsInfoIgnoresNonProviderKeys(t *testing.T) {
	t.Parallel()

	sess := newTestSession(t)

	err := cache.UpsertWithTTL(sess.Logger, sess.Cache, cache.Item{
		Key:     "metadata_other",
		Value:   []byte(`{"data":"test"}`),
		Created: time.Now(),
	}, time.Hour)
	require.NoError(t, err)

	c := &Client{Sess: sess}

	items, err := c.GetCacheItemsInfo()
	require.NoError(t, err)
	require.Empty(t, items)
}

// newOnDiskSession builds a session whose HomeDir contains a pre-populated,
// closed on-disk cache. Get/Delete re-open that cache themselves, so the session
// must not hold the directory lock. Returns the session and the cache key seeded.
func newOnDiskSession(t *testing.T, seed *cache.Item) *session.Session {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	homeDir := t.TempDir()

	sess := &session.Session{
		Logger: lg,
		Stats:  session.CreateStats(),
	}
	sess.Config.Global.HomeDir = homeDir

	if seed != nil {
		db, err := cache.Create(lg, filepath.Join(homeDir, ".config", "ipscout"))
		require.NoError(t, err)
		require.NoError(t, cache.UpsertWithTTL(lg, db, *seed, time.Hour))
		require.NoError(t, db.Close())
	}

	return sess
}

func TestGet(t *testing.T) {
	t.Parallel()

	key := "testkey"

	sess := newOnDiskSession(t, &cache.Item{
		Key:        key,
		Value:      []byte(`{"hello":"world"}`),
		AppVersion: "1.0.0",
		Version:    "v1",
		Created:    time.Now(),
	})

	c := &Client{Sess: sess}

	// Get opens, uses, and defer-closes its own cache handle internally.
	require.NoError(t, c.Get(key, false))
}

func TestGetRaw(t *testing.T) {
	t.Parallel()

	key := "rawkey"

	sess := newOnDiskSession(t, &cache.Item{
		Key:     key,
		Value:   []byte(`{"raw":true}`),
		Created: time.Now(),
	})

	c := &Client{Sess: sess}

	require.NoError(t, c.Get(key, true))
}

func TestGetMissingKey(t *testing.T) {
	t.Parallel()

	sess := newOnDiskSession(t, nil)

	c := &Client{Sess: sess}

	err := c.Get("does-not-exist", false)
	require.Error(t, err)
}

func TestDelete(t *testing.T) {
	t.Parallel()

	key := "delkey"

	sess := newOnDiskSession(t, &cache.Item{
		Key:     key,
		Value:   []byte(`{"del":true}`),
		Created: time.Now(),
	})

	c := &Client{Sess: sess}

	require.NoError(t, c.Delete([]string{key}))
}
