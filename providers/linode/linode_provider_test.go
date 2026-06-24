package linode

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	fetcher "github.com/jonhadfield/ip-fetcher/providers/linode"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	// testHost is an address contained within the testdata prefix 69.164.198.0/24.
	testHost = "69.164.198.1"
	// testPrefix is the prefix present in the testdata report.
	testPrefix = "69.164.198.0/24"
	// defaultMatchScore is the rating score used in the rating config fixtures.
	defaultMatchScore = 5.0
	// testPriority is an arbitrary output priority value used for assertions.
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
	pc.Providers.Linode.Enabled = &enabled
	require.True(t, pc.Enabled())

	// Explicitly disabled.
	enabled = false

	require.False(t, pc.Enabled())

	// UseTestData always enables regardless of config.
	pc.Providers.Linode.Enabled = nil
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := testPriority
	pc.Providers.Linode.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	cfg := c.GetConfig()
	require.NotNil(t, cfg)
	require.True(t, cfg.UseTestData)
}

func TestInitialise(t *testing.T) {
	t.Parallel()

	// Missing cache -> error.
	pc := &ProviderClient{}
	pc.Stats = session.CreateStats()
	pc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	pc.Host = netip.MustParseAddr(testHost)
	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)

	// Cache pre-populated with provider data -> Initialise succeeds without any
	// network fetch (CheckExists returns true so loadProviderData is skipped).
	c := newTestProviderClient(t)
	seedProviderCache(t, c)
	require.NoError(t, c.Initialise())
}

// seedProviderCache writes a minimal provider document into the cache so that
// Initialise finds it and avoids attempting a network fetch.
func seedProviderCache(t *testing.T, c *ProviderClient) {
	t.Helper()

	err := cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      []byte(`{"records":[]}`),
		Created:    time.Now(),
	}, DocTTL)
	require.NoError(t, err)
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	// The returned bytes should be the raw report we can re-parse.
	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Prefix)
	require.Equal(t, "US", parsed.Alpha2Code)
	require.Equal(t, "US-TX", parsed.Region)
	require.Equal(t, "Richardson", parsed.City)
}

func TestFindHostFromCache(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	// Drive the cache-backed search path rather than the test-data shortcut.
	c.UseTestData = false

	doc := fetcher.Doc{
		ETag: "etag-test",
		Records: []fetcher.Record{
			{
				Prefix:     netip.MustParsePrefix(testPrefix),
				Alpha2Code: "US",
				Region:     "US-TX",
				City:       "Richardson",
				PostalCode: "75081",
			},
		},
	}

	raw, err := json.Marshal(doc)
	require.NoError(t, err)

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      raw,
		Created:    time.Now(),
	}, DocTTL)
	require.NoError(t, err)

	res, err := c.FindHost()
	require.NoError(t, err)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Prefix)
	require.Equal(t, "Richardson", parsed.City)
	require.Equal(t, "etag-test", parsed.SyncToken)
}

func TestFindHostNoMatch(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false

	// Empty record set -> the host cannot match.
	raw, err := json.Marshal(fetcher.Doc{Records: []fetcher.Record{}})
	require.NoError(t, err)

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      raw,
		Created:    time.Now(),
	}, DocTTL)
	require.NoError(t, err)

	_, err = c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestCreateTable(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	tw, err := c.CreateTable(data)
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, testHost)
	require.Contains(t, rendered, "Richardson")
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	indicators, err := c.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "true", indicators.Indicators["HostedInLinode"])
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	ratingConfigJSON := `{
		"providers": {
			"linode": {
				"defaultMatchScore": 5.0
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, defaultMatchScore, result.Score)
	require.Equal(t, []string{"source is Linode"}, result.Reasons)
}

func TestRateHostDataNoMatch(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// A document with an invalid (zero) prefix should not be detected.
	emptyDoc, err := json.Marshal(HostSearchResult{})
	require.NoError(t, err)

	ratingConfigJSON := `{"providers":{"linode":{"defaultMatchScore":5.0}}}`

	result, err := c.RateHostData(emptyDoc, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.False(t, result.Detected)
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"ip_prefix":"69.164.198.0/24","alpha2code":"US","region":"US-TX","city":"Richardson"}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
	require.Equal(t, "US", res.Alpha2Code)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := loadResultsFile("testdata/linode_69_164_198_1_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
	require.Equal(t, "Richardson", res.City)
}
