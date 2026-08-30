package ahrefs

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	fetcherAhrefs "github.com/jonhadfield/ip-fetcher/providers/ahrefs"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

// Values that match providers/ahrefs/testdata/ahrefs_54_36_148_1_report.json.
const (
	testHost         = "54.36.148.1"
	testPrefix       = "54.36.148.0/23"
	testDefaultScore = 7.5
	testCreationRFC  = "2024-11-14T00:00:00Z"
	// The live ahrefs feed carries no IPv6 prefixes, so IPv6 coverage uses a
	// documentation prefix (RFC 3849) in synthetic seed data.
	testIPv6Prefix = "2001:db8:a4ef::/48"
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

// seedCache writes an ahrefs provider document into the cache so that the
// non-test-data code paths (Initialise hit, loadProviderDataFromCache, FindHost
// search) can run without any network access.
func seedCache(t *testing.T, c *ProviderClient) {
	t.Helper()

	doc := fetcherAhrefs.Doc{
		CreationTime: time.Date(2024, 11, 14, 0, 0, 0, 0, time.UTC),
		IPv4Prefixes: []fetcherAhrefs.IPv4Entry{
			{IPv4Prefix: netip.MustParsePrefix(testPrefix)},
		},
		IPv6Prefixes: []fetcherAhrefs.IPv6Entry{
			{IPv6Prefix: netip.MustParsePrefix(testIPv6Prefix)},
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

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}

	// Disabled by default.
	require.False(t, pc.Enabled())

	// Enabled flag set -> enabled.
	enabled := true
	pc.Providers.Ahrefs.Enabled = &enabled
	require.True(t, pc.Enabled())

	// Explicitly disabled flag -> disabled.
	enabled = false

	require.False(t, pc.Enabled())

	// UseTestData always enables regardless of config.
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := int32(9)
	pc.Providers.Ahrefs.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	cfg := c.GetConfig()
	require.NotNil(t, cfg)
	require.True(t, cfg.UseTestData)
}

func TestInitialiseCacheNotSet(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	pc.Stats = session.CreateStats()
	pc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	pc.Host = netip.MustParseAddr(testHost)

	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)
}

func TestInitialiseCachePresent(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// Seed provider data so Initialise finds it in cache and avoids the network.
	seedCache(t, c)

	require.NoError(t, c.Initialise())
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Prefix)
	// The live ahrefs feed carries no creationTime, so the fixture omits it.
	require.True(t, parsed.CreationTime.IsZero())
}

func TestFindHostFromCacheIPv4(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	seedCache(t, c)

	res, err := c.FindHost()
	require.NoError(t, err)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Prefix)
}

func TestFindHostFromCacheNoMatch(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.MustParseAddr("203.0.113.1")
	seedCache(t, c)

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestFindHostFromCacheIPv6(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.MustParseAddr("2001:db8:a4ef::1")
	seedCache(t, c)

	res, err := c.FindHost()
	require.NoError(t, err)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testIPv6Prefix), parsed.Prefix)
}

func TestFindHostCacheMissing(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false

	// No data seeded in cache -> read failure.
	_, err := c.FindHost()
	require.Error(t, err)
}

func TestFindHostCacheCorrupt(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false

	err := cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      []byte("not-json"),
		Version:    "v1",
		Created:    time.Now(),
	}, DocTTL)
	require.NoError(t, err)

	_, err = c.FindHost()
	require.Error(t, err)
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
	require.Equal(t, "true", indicators.Indicators["AhrefsBot"])
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	ratingConfigJSON := `{
		"providers": {
			"ahrefs": {
				"defaultMatchScore": 7.5
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.InEpsilon(t, testDefaultScore, result.Score, 0.0001)
	require.Equal(t, []string{"source is AhrefsBot"}, result.Reasons)
}

func TestRateHostDataNoPrefix(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// A HostSearchResult with no (invalid) prefix should not be detected.
	data := []byte(`{"creation_time":"` + testCreationRFC + `"}`)

	ratingConfigJSON := `{"providers":{"ahrefs":{"defaultMatchScore":7.5}}}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.False(t, result.Detected)
	require.Zero(t, result.Score)
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"prefix":"` + testPrefix + `","creation_time":"` + testCreationRFC + `"}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
	require.False(t, res.CreationTime.IsZero())
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestUnmarshalResponseError(t *testing.T) {
	t.Parallel()

	_, err := unmarshalResponse([]byte("not-json"))
	require.Error(t, err)
}

func TestUnmarshalProviderDataError(t *testing.T) {
	t.Parallel()

	_, err := unmarshalProviderData([]byte("not-json"))
	require.Error(t, err)
}

func TestExtractThreatIndicatorsError(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	_, err := c.ExtractThreatIndicators([]byte("not-json"))
	require.Error(t, err)
}

func TestRateHostDataBadConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	_, err := c.RateHostData([]byte(`{}`), []byte("not-json"))
	require.Error(t, err)
}

func TestRateHostDataBadFindResult(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	_, err := c.RateHostData([]byte("not-json"), []byte(`{}`))
	require.Error(t, err)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := fetcherAhrefs.Doc{
		CreationTime: time.Date(2024, 11, 14, 0, 0, 0, 0, time.UTC),
		IPv4Prefixes: []fetcherAhrefs.IPv4Entry{
			{IPv4Prefix: netip.MustParsePrefix(testPrefix)},
		},
	}

	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.CreationTime, res.CreationTime)
	require.Equal(t, doc.IPv4Prefixes[0].IPv4Prefix, res.IPv4Prefixes[0].IPv4Prefix)
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := providers.LoadResultsFile[HostSearchResult]("testdata/ahrefs_54_36_148_1_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
}
