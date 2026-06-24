package bingbot

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	ipfbingbot "github.com/jonhadfield/ip-fetcher/providers/bingbot"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	// testHost is an address inside the testdata prefix (157.55.39.0/24).
	testHost = "157.55.39.10"
	// defaultMatchScore is the rating score asserted from the rating config.
	defaultMatchScore = 5.0
)

// newTestProviderClient builds a ProviderClient backed by a temporary cache and
// the UseTestData path, so the real provider logic runs without any network access.
func newTestProviderClient(t *testing.T) *ProviderClient {
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

	return pc.(*ProviderClient)
}

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}

	// Disabled by default.
	require.False(t, pc.Enabled())

	// Enabled flag set -> enabled.
	enabled := true
	pc.Providers.Bingbot.Enabled = &enabled
	require.True(t, pc.Enabled())

	// Explicitly disabled.
	enabled = false

	require.False(t, pc.Enabled())

	// UseTestData always enables regardless of config.
	pc.Providers.Bingbot.Enabled = nil
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := int32(5)
	pc.Providers.Bingbot.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	require.NotNil(t, c.GetConfig())
	require.True(t, c.GetConfig().UseTestData)
}

func TestInitialiseCacheNotSet(t *testing.T) {
	t.Parallel()

	// Missing cache -> error.
	pc := &ProviderClient{}
	pc.Stats = session.CreateStats()
	pc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	pc.Host = netip.MustParseAddr(testHost)
	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)
}

// seedProviderCache writes a bingbot provider Doc into the cache so the
// non-test-data code paths (Initialise cache hit, loadProviderDataFromCache,
// FindHost over real data) can run without any network access.
func seedProviderCache(t *testing.T, c *ProviderClient) {
	t.Helper()

	doc := ipfbingbot.Doc{
		CreationTime: time.Now(),
		IPv4Prefixes: []ipfbingbot.IPv4Entry{
			{IPv4Prefix: netip.MustParsePrefix("157.55.39.0/24")},
		},
		IPv6Prefixes: []ipfbingbot.IPv6Entry{
			{IPv6Prefix: netip.MustParsePrefix("2620:1ec:c11::/48")},
		},
	}

	data, err := json.Marshal(doc)
	require.NoError(t, err)

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.CreationTime.String(),
		Created:    time.Now(),
	}, DocTTL)
	require.NoError(t, err)
}

func TestInitialiseCacheHit(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	seedProviderCache(t, c)

	// Provider data already in cache -> Initialise returns without fetching.
	require.NoError(t, c.Initialise())
}

func TestLoadProviderDataFromCache(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	seedProviderCache(t, c)

	doc, err := c.loadProviderDataFromCache()
	require.NoError(t, err)
	require.NotEmpty(t, doc.IPv4Prefixes)
	require.NotEmpty(t, doc.IPv6Prefixes)
}

func TestFindHostFromCacheIPv4(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	seedProviderCache(t, c)

	// Drive the real (non-test-data) lookup path against the seeded cache.
	c.UseTestData = false
	c.Host = netip.MustParseAddr(testHost)

	res, err := c.FindHost()
	require.NoError(t, err)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("157.55.39.0/24"), parsed.Prefix)
}

func TestFindHostFromCacheNoMatch(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	seedProviderCache(t, c)

	c.UseTestData = false
	c.Host = netip.MustParseAddr("8.8.8.8")

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := ipfbingbot.Doc{
		CreationTime: time.Now(),
		IPv4Prefixes: []ipfbingbot.IPv4Entry{
			{IPv4Prefix: netip.MustParsePrefix("157.55.39.0/24")},
		},
	}

	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.IPv4Prefixes[0].IPv4Prefix, res.IPv4Prefixes[0].IPv4Prefix)
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	// The returned bytes should re-parse into the fixture prefix.
	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("157.55.39.0/24"), parsed.Prefix)
	require.False(t, parsed.CreationTime.IsZero())
}

func TestCreateTable(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	tw, err := c.CreateTable(data)
	require.NoError(t, err)
	require.NotNil(t, tw)
	require.NotEmpty(t, (*tw).Render())
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	indicators, err := c.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "true", indicators.Indicators["ReputableBot"])
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	ratingConfigJSON := `{
		"providers": {
			"bingbot": {
				"defaultMatchScore": 5.0
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, defaultMatchScore, result.Score)
	require.Equal(t, []string{"hosted in Bingbot"}, result.Reasons)
}

func TestRateHostDataInvalidPrefix(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}

	// A zero/invalid prefix is not detected and yields no score.
	result, err := pc.RateHostData([]byte(`{}`), []byte(`{}`))
	require.NoError(t, err)
	require.False(t, result.Detected)
	require.InDelta(t, 0.0, result.Score, 0.0)
}

func TestRateHostDataInvalidRatingConfig(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}

	// Malformed rating config JSON -> error.
	_, err := pc.RateHostData([]byte(`{}`), []byte(`{`))
	require.Error(t, err)
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"prefix":"157.55.39.0/24"}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("157.55.39.0/24"), res.Prefix)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := loadResultsFile("testdata/bingbot_157_55_39_0_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("157.55.39.0/24"), res.Prefix)
	require.False(t, res.CreationTime.IsZero())
}
