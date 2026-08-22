package anthropic

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	fetcherAnthropic "github.com/jonhadfield/ip-fetcher/providers/anthropic"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

// Values that match providers/anthropic/testdata/anthropic_160_79_104_10_report.json.
const (
	testHost         = "160.79.104.10"
	testPrefix       = "160.79.104.0/23"
	testDefaultScore = 1.0
	testCreationRFC  = "2025-08-05T09:12:00Z"
	testIPv6Prefix   = "2607:6bc0::/48"
	testIPv6Host     = "2607:6bc0::1"
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

// seedCache writes an anthropic provider document into the cache so that the
// non-test-data code paths (Initialise hit, loadProviderDataFromCache, FindHost
// search) can run without any network access.
func seedCache(t *testing.T, c *ProviderClient) {
	t.Helper()

	doc := fetcherAnthropic.Doc{
		CreationTime: time.Date(2025, 8, 5, 9, 12, 0, 0, time.UTC),
		IPv4Prefixes: []fetcherAnthropic.IPv4Entry{
			{IPv4Prefix: netip.MustParsePrefix(testPrefix)},
		},
		IPv6Prefixes: []fetcherAnthropic.IPv6Entry{
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
	pc.Providers.Anthropic.Enabled = &enabled
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
	pc.Providers.Anthropic.OutputPriority = &priority
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
	require.False(t, parsed.CreationTime.IsZero())
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

func TestFindHostFromCacheIPv6(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.MustParseAddr(testIPv6Host)
	seedCache(t, c)

	res, err := c.FindHost()
	require.NoError(t, err)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testIPv6Prefix), parsed.Prefix)
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

func TestCreateTableError(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	_, err := c.CreateTable([]byte("not-json"))
	require.Error(t, err)
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	indicators, err := c.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "true", indicators.Indicators["Anthropic"])
}

func TestExtractThreatIndicatorsError(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	_, err := c.ExtractThreatIndicators([]byte("not-json"))
	require.Error(t, err)
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	ratingConfigJSON := `{
		"providers": {
			"anthropic": {
				"defaultMatchScore": 1.0
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.InEpsilon(t, testDefaultScore, result.Score, 0.0001)
	require.Equal(t, []string{"source is Anthropic"}, result.Reasons)
}

func TestRateHostDataNoPrefix(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// A HostSearchResult with no (invalid) prefix should not be detected.
	data := []byte(`{"creation_time":"` + testCreationRFC + `"}`)

	ratingConfigJSON := `{"providers":{"anthropic":{"defaultMatchScore":1.0}}}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.False(t, result.Detected)
	require.Zero(t, result.Score)
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

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := fetcherAnthropic.Doc{
		CreationTime: time.Date(2025, 8, 5, 9, 12, 0, 0, time.UTC),
		IPv4Prefixes: []fetcherAnthropic.IPv4Entry{
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

func TestUnmarshalProviderDataError(t *testing.T) {
	t.Parallel()

	_, err := unmarshalProviderData([]byte("not-json"))
	require.Error(t, err)
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := providers.LoadResultsFile[HostSearchResult]("testdata/anthropic_160_79_104_10_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
	require.False(t, res.CreationTime.IsZero())
}

// mockTransport returns a canned response for any request, so the real
// loadProviderData -> ip-fetcher Fetch network path can run offline.
type mockTransport struct {
	status int
	body   []byte
}

func (m mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(bytes.NewReader(m.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func mockHTTPClient(status int, body []byte) *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.Logger = nil
	hc.RetryMax = 0
	hc.HTTPClient.Transport = mockTransport{status: status, body: body}

	return hc
}

// newMockedClient wires a ProviderClient to a mocked HTTP client serving the
// upstream anthropic fixture, plus a real temp cache, with UseTestData off.
func newMockedClient(t *testing.T, status int, body []byte) *ProviderClient {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := session.Session{
		Logger:     lg,
		Stats:      session.CreateStats(),
		Cache:      db,
		HTTPClient: mockHTTPClient(status, body),
	}
	sess.Host = netip.MustParseAddr(testHost)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestInitialiseAndFindHostOverNetwork(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("testdata/anthropic.json")
	require.NoError(t, err)

	c := newMockedClient(t, http.StatusOK, body)

	// Initialise on an empty cache triggers loadProviderData -> ip-fetcher Fetch,
	// served by the mock transport, then caches the parsed Doc.
	require.NoError(t, c.Initialise())

	// FindHost reads the now-populated cache and matches the host to a prefix.
	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Prefix)
}

func TestInitialiseNetworkFetchError(t *testing.T) {
	t.Parallel()

	// ip-fetcher never rejects on HTTP status, so an upstream error page only
	// fails when its body cannot be parsed: a 200 with an unparseable body
	// makes Fetch fail, surfacing from loadProviderData.
	c := newMockedClient(t, http.StatusOK, []byte("boom"))

	require.Error(t, c.Initialise())
}

func TestInitialiseEmptyDocumentNotCached(t *testing.T) {
	t.Parallel()

	// A valid but empty upstream document (no prefixes) parses without error;
	// caching it would blank all lookups until the document TTL expires, so
	// Initialise must fail with ErrFailedToFetchData and cache nothing.
	body := []byte(`{"creationTime":"2025-08-05T09:12:00.000000","prefixes":[]}`)
	c := newMockedClient(t, http.StatusOK, body)

	err := c.Initialise()
	require.Error(t, err)
	require.ErrorIs(t, err, providers.ErrFailedToFetchData)

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestFindHostInvalidHost(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.Addr{}
	seedCache(t, c)

	_, err := c.FindHost()
	require.Error(t, err)
}
