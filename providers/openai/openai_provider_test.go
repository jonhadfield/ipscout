package openai

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	fetcherOpenAI "github.com/jonhadfield/ip-fetcher/providers/openai"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

// Values that match providers/openai/testdata/openai_20_171_206_1_report.json.
const (
	testHost         = "20.171.206.1"
	testPrefix       = "20.171.206.0/24"
	testDefaultScore = 1.5
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

// seedCache writes an openai provider document into the cache so that the
// non-test-data code paths (Initialise hit, loadProviderDataFromCache, FindHost
// search) can run without any network access. The ChatGPT-User list contains a
// prefix overlapping the GPTBot one so multi-list matches can be exercised.
func seedCache(t *testing.T, c *ProviderClient) {
	t.Helper()

	doc := fetcherOpenAI.Doc{
		GPTBot: fetcherOpenAI.List{
			CreationTime: time.Date(2025, 10, 30, 11, 0, 0, 0, time.UTC),
			IPv4Prefixes: []fetcherOpenAI.IPv4Entry{
				{IPv4Prefix: netip.MustParsePrefix(testPrefix)},
			},
			IPv6Prefixes: []fetcherOpenAI.IPv6Entry{
				{IPv6Prefix: netip.MustParsePrefix("2001:db8::/32")},
			},
		},
		SearchBot: fetcherOpenAI.List{
			CreationTime: time.Date(2026, 1, 2, 11, 0, 0, 0, time.UTC),
			IPv4Prefixes: []fetcherOpenAI.IPv4Entry{
				{IPv4Prefix: netip.MustParsePrefix("104.210.140.128/28")},
			},
		},
		ChatGPTUser: fetcherOpenAI.List{
			CreationTime: time.Date(2026, 7, 8, 21, 2, 54, 0, time.UTC),
			IPv4Prefixes: []fetcherOpenAI.IPv4Entry{
				{IPv4Prefix: netip.MustParsePrefix("20.171.206.0/23")},
			},
		},
	}

	data, err := json.Marshal(doc)
	require.NoError(t, err)

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.GPTBot.CreationTime.String(),
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
	pc.Providers.OpenAI.Enabled = &enabled
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
	pc.Providers.OpenAI.OutputPriority = &priority
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
	require.Len(t, parsed.Matches, 1)
	require.Equal(t, fetcherOpenAI.GPTBotName, parsed.Matches[0].Name)
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Matches[0].Prefix)
	require.False(t, parsed.Matches[0].CreationTime.IsZero())
}

func TestFindHostFromCacheIPv4MultipleBots(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	seedCache(t, c)

	res, err := c.FindHost()
	require.NoError(t, err)

	// The host is in both the GPTBot and ChatGPT-User lists.
	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Len(t, parsed.Matches, 2)
	require.Equal(t, fetcherOpenAI.GPTBotName, parsed.Matches[0].Name)
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Matches[0].Prefix)
	require.Equal(t, fetcherOpenAI.ChatGPTUserName, parsed.Matches[1].Name)
	require.Equal(t, netip.MustParsePrefix("20.171.206.0/23"), parsed.Matches[1].Prefix)
}

func TestFindHostFromCacheSearchBot(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.MustParseAddr("104.210.140.130")
	seedCache(t, c)

	res, err := c.FindHost()
	require.NoError(t, err)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Len(t, parsed.Matches, 1)
	require.Equal(t, fetcherOpenAI.SearchBotName, parsed.Matches[0].Name)
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
	c.Host = netip.MustParseAddr("2001:db8::1")
	seedCache(t, c)

	res, err := c.FindHost()
	require.NoError(t, err)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Len(t, parsed.Matches, 1)
	require.Equal(t, fetcherOpenAI.GPTBotName, parsed.Matches[0].Name)
	require.Equal(t, netip.MustParsePrefix("2001:db8::/32"), parsed.Matches[0].Prefix)
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

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, "GPTBot")
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
			"openai": {
				"defaultMatchScore": 1.5
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, testDefaultScore, result.Score)
	require.Equal(t, []string{"source is OpenAI GPTBot"}, result.Reasons)
}

func TestRateHostDataNoMatches(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// A HostSearchResult with no matches should not be detected.
	data := []byte(`{"matches":[]}`)

	ratingConfigJSON := `{"providers":{"openai":{"defaultMatchScore":1.5}}}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.Error(t, err)
	require.False(t, result.Detected)
	require.Zero(t, result.Score)
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"matches":[{"name":"GPTBot","prefix":"` + testPrefix + `","creation_time":"2025-10-30T11:00:00Z"}]}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Len(t, res.Matches, 1)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Matches[0].Prefix)
	require.False(t, res.Matches[0].CreationTime.IsZero())
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

	doc := fetcherOpenAI.Doc{
		GPTBot: fetcherOpenAI.List{
			CreationTime: time.Date(2025, 10, 30, 11, 0, 0, 0, time.UTC),
			IPv4Prefixes: []fetcherOpenAI.IPv4Entry{
				{IPv4Prefix: netip.MustParsePrefix(testPrefix)},
			},
		},
	}

	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.GPTBot.CreationTime, res.GPTBot.CreationTime)
	require.Equal(t, doc.GPTBot.IPv4Prefixes[0].IPv4Prefix, res.GPTBot.IPv4Prefixes[0].IPv4Prefix)
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := loadResultsFile("testdata/openai_20_171_206_1_report.json")
	require.NoError(t, err)
	require.Len(t, res.Matches, 1)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Matches[0].Prefix)
	require.False(t, res.Matches[0].CreationTime.IsZero())
}
