package googlesc

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	fetcherGoogleSC "github.com/jonhadfield/ip-fetcher/providers/googlesc"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	testHost           = "74.125.219.32"
	testPrefix         = "74.125.219.32/27"
	testDefaultScore   = 5.0
	testOutputPriority = int32(7)
)

// seedProviderCache stores a valid googlesc provider doc so Initialise finds
// fresh data in the cache and never attempts a network fetch.
func seedProviderCache(t *testing.T, c *ProviderClient) {
	t.Helper()

	doc := fetcherGoogleSC.Doc{
		CreationTime: time.Now(),
		IPv4Prefixes: []fetcherGoogleSC.IPv4Entry{
			{IPv4Prefix: netip.MustParsePrefix(testPrefix)},
		},
	}

	data, err := json.Marshal(doc)
	require.NoError(t, err)

	require.NoError(t, cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.CreationTime.String(),
		Created:    time.Now(),
	}, DocTTL))
}

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
	pc.Providers.GoogleSC.Enabled = &enabled
	require.True(t, pc.Enabled())

	// Disabled flag -> disabled.
	enabled = false
	pc.Providers.GoogleSC.Enabled = &enabled
	require.False(t, pc.Enabled())

	// UseTestData always enables regardless of config.
	pc.Providers.GoogleSC.Enabled = nil
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := testOutputPriority
	pc.Providers.GoogleSC.OutputPriority = &priority
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

	// Cache present and pre-seeded with provider data -> success. Seeding ensures
	// Initialise finds the data via CheckExists and never attempts a network fetch.
	c := newTestProviderClient(t)
	seedProviderCache(t, c)
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
	require.False(t, parsed.CreationTime.IsZero())
}

func TestFindHostFromCache(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	// Drive the real cache-backed lookup path rather than the test-data shortcut.
	c.UseTestData = false
	seedProviderCache(t, c)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Prefix)
}

func TestFindHostNoMatch(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.MustParseAddr("203.0.113.1") // outside seeded prefix
	seedProviderCache(t, c)

	_, err := c.FindHost()
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
	require.Contains(t, rendered, testPrefix)
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
			"googlesc": {
				"defaultMatchScore": 5.0
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, testDefaultScore, result.Score)
	require.Equal(t, []string{"source is GoogleSC"}, result.Reasons)
}

func TestRateHostDataNoPrefix(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// A document with an invalid/zero prefix should not be detected.
	data := []byte(`{}`)

	result, err := c.RateHostData(data, []byte(`{"providers":{"googlesc":{"defaultMatchScore":5.0}}}`))
	require.NoError(t, err)
	require.False(t, result.Detected)
	require.Zero(t, result.Score)
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"prefix":"74.125.219.32/27","creation_time":"2024-05-25T22:00:14Z"}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
	require.False(t, res.CreationTime.IsZero())
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := loadResultsFile("testdata/googlesc_74_125_219_32_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
	require.False(t, res.CreationTime.IsZero())
}

func TestExtractThreatIndicatorsEmpty(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}

	// No prefix -> no ReputableBot indicator, but the call still succeeds.
	indicators, err := pc.ExtractThreatIndicators([]byte(`{}`))
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	_, ok := indicators.Indicators["ReputableBot"]
	require.False(t, ok)
}

func TestUnmarshalResponseError(t *testing.T) {
	t.Parallel()

	_, err := unmarshalResponse([]byte(`not-json`))
	require.Error(t, err)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := fetcherGoogleSC.Doc{
		CreationTime: time.Now(),
		IPv4Prefixes: []fetcherGoogleSC.IPv4Entry{
			{IPv4Prefix: netip.MustParsePrefix(testPrefix)},
		},
	}

	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.IPv4Prefixes[0].IPv4Prefix, res.IPv4Prefixes[0].IPv4Prefix)

	_, err = unmarshalProviderData([]byte(`not-json`))
	require.Error(t, err)
}

func TestRateHostDataBadFindResult(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}

	_, err := pc.RateHostData([]byte(`not-json`), []byte(`{}`))
	require.Error(t, err)

	// Invalid rating config JSON should also error.
	_, err = pc.RateHostData([]byte(`{}`), []byte(`not-json`))
	require.Error(t, err)
}

func TestExtractThreatIndicatorsBadJSON(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}

	_, err := pc.ExtractThreatIndicators([]byte(`not-json`))
	require.Error(t, err)
}

func TestRateHostDataMarshalProducesValidJSON(t *testing.T) {
	t.Parallel()

	res := HostSearchResult{Prefix: netip.MustParsePrefix(testPrefix)}

	b, err := json.Marshal(res)
	require.NoError(t, err)

	parsed, err := unmarshalResponse(b)
	require.NoError(t, err)
	require.Equal(t, res.Prefix, parsed.Prefix)
}
