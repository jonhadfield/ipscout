package ptr

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const testHost = "8.8.8.8"

// newTestClient builds a *Client backed by a temporary cache and the UseTestData
// path, so the real provider logic runs without any network access.
func newTestClient(t *testing.T) *Client {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := session.Session{
		Logger: lg,
		Stats:  session.CreateStats(),
		Cache:  db,
	}
	sess.UseTestData = true
	sess.Host = netip.MustParseAddr(testHost)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*Client)
}

func TestEnabled(t *testing.T) {
	t.Parallel()

	c := &Client{}

	// Disabled by default.
	require.False(t, c.Enabled())

	// Enabled flag set -> enabled.
	enabled := true
	c.Providers.PTR.Enabled = &enabled
	require.True(t, c.Enabled())

	// Explicitly disabled flag -> disabled.
	enabled = false

	require.False(t, c.Enabled())

	// UseTestData always enables regardless of config.
	c.Providers.PTR.Enabled = nil
	c.UseTestData = true
	require.True(t, c.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	c := &Client{}
	require.Nil(t, c.Priority())

	priority := int32(5)
	c.Providers.PTR.OutputPriority = &priority
	require.Equal(t, priority, *c.Priority())
}

func TestInitialise(t *testing.T) {
	t.Parallel()

	// Missing cache -> error.
	c := &Client{}
	c.Stats = session.CreateStats()
	c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	c.Host = netip.MustParseAddr(testHost)
	require.ErrorIs(t, c.Initialise(), session.ErrCacheNotSet)

	// Cache present -> success.
	tc := newTestClient(t)
	require.NoError(t, tc.Initialise())
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	// The returned bytes should be the raw ptr response we can re-parse.
	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Len(t, parsed.RR, 1)
	require.Equal(t, "dns.google.", parsed.RR[0].Ptr)
	require.Equal(t, "8.8.8.8.in-addr.arpa.", parsed.RR[0].Header.Name)
}

func TestCreateTable(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	tw, err := c.CreateTable(data)
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, "dns.google.")
}

func TestCreateTableNoData(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	// No RR entries -> error.
	tw, err := c.CreateTable([]byte(`{"rr":[]}`))
	require.Error(t, err)
	require.Nil(t, tw)
}

func TestCreateTableInvalidJSON(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	tw, err := c.CreateTable([]byte("not json"))
	require.Error(t, err)
	require.Nil(t, tw)
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	indicators, err := c.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Nil(t, indicators)
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	result, err := c.RateHostData(data, []byte(`{}`))
	require.NoError(t, err)
	require.False(t, result.Detected)
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	cfg := c.GetConfig()
	require.NotNil(t, cfg)
	require.Equal(t, testHost, cfg.Host.String())
}
