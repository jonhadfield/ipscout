package hetzner

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	ipfhetzner "github.com/jonhadfield/ip-fetcher/providers/hetzner"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	// testPrefix matches the prefix in testdata/hetzner.txt and is a real
	// Hetzner IPv4 prefix from testdata/hetzner.json.
	testPrefix = "5.9.0.0/16"
	// testHost is an address inside testPrefix.
	testHost = "5.9.1.1"
	// testPrefixV6 is a real Hetzner IPv6 prefix from testdata/hetzner.json.
	testPrefixV6 = "2a01:4f8::/32"
	// testHostV6 is an address inside testPrefixV6.
	testHostV6 = "2a01:4f8::1"
	// testMatchScore is an arbitrary score used to drive the rating config.
	testMatchScore = 5.0
	// testPriority is an arbitrary output priority value.
	testPriority = int32(7)
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
	pc.Providers.Hetzner.Enabled = &enabled
	require.True(t, pc.Enabled())

	// Enabled flag explicitly false -> disabled.
	enabled = false
	pc.Providers.Hetzner.Enabled = &enabled
	require.False(t, pc.Enabled())

	// UseTestData always enables regardless of config.
	pc.Providers.Hetzner.Enabled = nil
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := testPriority
	pc.Providers.Hetzner.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	require.NotNil(t, c.GetConfig())
	require.Equal(t, testHost, c.GetConfig().Host.String())
}

func TestInitialise(t *testing.T) {
	t.Parallel()

	// Missing cache -> error.
	pc := &ProviderClient{}
	pc.Stats = session.CreateStats()
	pc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	pc.Host = netip.MustParseAddr(testHost)
	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)
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
	require.NotEmpty(t, parsed.Raw)
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

	// Hetzner does not produce threat indicators.
	indicators, err := c.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Nil(t, indicators)
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	ratingConfigJSON := `{
		"providers": {
			"hetzner": {
				"defaultMatchScore": 5.0
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, testMatchScore, result.Score)
	require.Equal(t, []string{"hosted in Hetzner"}, result.Reasons)
}

func TestRateHostDataInvalidPrefix(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// An empty HostSearchResult marshals to an invalid prefix, which is not
	// detected and produces no error.
	data, err := json.Marshal(HostSearchResult{})
	require.NoError(t, err)

	result, err := c.RateHostData(data, []byte(`{"providers":{"hetzner":{}}}`))
	require.NoError(t, err)
	require.False(t, result.Detected)
}

func TestRateHostDataInvalidRatingConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	_, err = c.RateHostData(data, []byte(`{not-json`))
	require.Error(t, err)
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"prefix":"` + testPrefix + `"}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	data := []byte(`{"IPv4Prefixes":["` + testPrefix + `"],"IPv6Prefixes":["2a01:4f8::/32"]}`)

	doc, err := unmarshalProviderData(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), doc.IPv4Prefixes[0])
	require.Equal(t, netip.MustParsePrefix("2a01:4f8::/32"), doc.IPv6Prefixes[0])
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := loadResultsFile("testdata/hetzner.txt")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
}

// seedCache stores a hetzner provider Doc in the cache so the non-test-data
// code paths can read real data without any network access.
func seedCache(t *testing.T, c *ProviderClient) {
	t.Helper()

	doc := ipfhetzner.Doc{
		IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix(testPrefix)},
		IPv6Prefixes: []netip.Prefix{netip.MustParsePrefix(testPrefixV6)},
	}

	data, err := json.Marshal(doc)
	require.NoError(t, err)

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, DocTTL)
	require.NoError(t, err)
}

func TestInitialiseUsesExistingCache(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false

	seedCache(t, c)

	// Cache already populated -> Initialise returns without fetching.
	require.NoError(t, c.Initialise())
}

func TestFindHostFromCacheIPv4(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.MustParseAddr(testHost)

	seedCache(t, c)

	res, err := c.FindHost()
	require.NoError(t, err)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Prefix)
}

func TestFindHostFromCacheIPv6(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.MustParseAddr(testHostV6)

	seedCache(t, c)

	res, err := c.FindHost()
	require.NoError(t, err)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefixV6), parsed.Prefix)
}

func TestFindHostNoMatch(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.MustParseAddr("203.0.113.1")

	seedCache(t, c)

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestLoadProviderDataFromCache(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false

	seedCache(t, c)

	doc, err := c.loadProviderDataFromCache()
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), doc.IPv4Prefixes[0])
	require.Equal(t, netip.MustParsePrefix(testPrefixV6), doc.IPv6Prefixes[0])
}
