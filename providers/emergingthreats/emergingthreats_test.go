package emergingthreats

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/emergingthreats"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	enabled := true
	pc.Providers.EmergingThreats.Enabled = &enabled
	require.True(t, pc.Enabled())

	enabled = false
	pc.UseTestData = true
	require.True(t, pc.Enabled())

	pc.UseTestData = false
	pc.Providers.EmergingThreats.Enabled = nil
	require.False(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	priority := int32(20)

	pc := &ProviderClient{}
	pc.Providers.EmergingThreats.OutputPriority = &priority

	require.Equal(t, &priority, pc.Priority())
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Equal(t, &pc.Session, pc.GetConfig())
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"prefix":"198.51.100.42/32"}`)
	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("198.51.100.42/32"), res.Prefix)
	require.JSONEq(t, string(data), string(res.Raw))

	_, err = unmarshalResponse([]byte(`{`))
	require.Error(t, err)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := ipfetcher.Doc{
		IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.42/32")},
		IPv6Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.IPv4Prefixes[0], res.IPv4Prefixes[0])
	require.Equal(t, doc.IPv6Prefixes[0], res.IPv6Prefixes[0])

	_, err = unmarshalProviderData([]byte(`not json`))
	require.Error(t, err)
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := providers.LoadResultsFile[HostSearchResult]("testdata/emergingthreats_198_51_100_42_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("198.51.100.42/32"), res.Prefix)
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix("198.51.100.42/32")}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	indicators, err := pc.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "true", indicators.Indicators["CompromisedHost"])

	empty, err := json.Marshal(HostSearchResult{})
	require.NoError(t, err)

	indicators, err = pc.ExtractThreatIndicators(empty)
	require.NoError(t, err)
	require.Empty(t, indicators.Indicators)

	_, err = pc.ExtractThreatIndicators([]byte(`{`))
	require.Error(t, err)
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix("198.51.100.42/32")}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	ratingConfigJSON := `{"providers":{"emergingthreats":{"defaultMatchScore":10.0}}}`

	result, err := pc.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.InEpsilon(t, 10.0, result.Score, 0.0001)
	// flat-score feeds leave Threat unset; only "noblock" is meaningful to rate/rate.go
	require.Empty(t, result.Threat)
	require.Equal(t, []string{"listed in Emerging Threats compromised IPs"}, result.Reasons)

	empty, err := json.Marshal(HostSearchResult{})
	require.NoError(t, err)

	result, err = pc.RateHostData(empty, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.False(t, result.Detected)
	require.Zero(t, result.Score)
	require.Empty(t, result.Reasons)

	_, err = pc.RateHostData(data, []byte(`{`))
	require.Error(t, err)

	_, err = pc.RateHostData([]byte(`{`), []byte(ratingConfigJSON))
	require.Error(t, err)
}

func newCacheSeededClient(t *testing.T, host string) *ProviderClient {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := session.Session{Logger: lg, Stats: session.CreateStats(), Cache: db}
	sess.Host = netip.MustParseAddr(host)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func seedCache(t *testing.T, c *ProviderClient, doc ipfetcher.Doc) {
	t.Helper()

	data, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		Key:     providers.CacheProviderPrefix + ProviderName,
		Value:   data,
		Created: time.Now(),
	}, time.Hour))
}

func TestInitialiseWithoutCache(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)
}

func TestInitialiseAndFindHostFromCache(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "198.51.100.42")
	seedCache(t, c, ipfetcher.Doc{IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.42/32")}})

	// cache present, so Initialise short-circuits without any network access
	require.NoError(t, c.Initialise())

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("198.51.100.42/32"), parsed.Prefix)

	tbl, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tbl)
}

func TestFindHostIPv6FromCache(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "2001:db8::1")
	seedCache(t, c, ipfetcher.Doc{IPv6Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}})

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("2001:db8::/32"), parsed.Prefix)
}

func TestFindHostNoMatch(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "203.0.113.5")
	seedCache(t, c, ipfetcher.Doc{IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.42/32")}})

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestFindHostInvalidHost(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "198.51.100.42")
	seedCache(t, c, ipfetcher.Doc{IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.42/32")}})
	c.Host = netip.Addr{}

	_, err := c.FindHost()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid")
}

func TestFindHostWithoutCachedData(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "198.51.100.42")

	_, err := c.FindHost()
	require.Error(t, err)
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "198.51.100.42")
	c.UseTestData = true

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("198.51.100.42/32"), parsed.Prefix)

	tbl, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tbl)
}

func TestCreateTableInvalidData(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "198.51.100.42")

	_, err := c.CreateTable([]byte(`{`))
	require.Error(t, err)
}

// mockTransport returns a canned response for any request, so the real
// loadProviderData -> ip-fetcher Fetch path can run offline.
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

// newMockedClient wires a ProviderClient to a mocked HTTP client serving an
// upstream emergingthreats list, plus a real temp cache, with UseTestData off.
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
	sess.Host = netip.MustParseAddr("198.51.100.42")

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestInitialiseAndFindHostFromSource(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, http.StatusOK, []byte("# compromised ips\n198.51.100.42\n2001:db8::1\n"))
	c.Providers.EmergingThreats.DocumentCacheTTL = 60

	// Initialise on an empty cache triggers loadProviderData -> ip-fetcher Fetch,
	// served by the mock transport, then caches the parsed Doc.
	require.NoError(t, c.Initialise())

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("198.51.100.42/32"), parsed.Prefix)
}

func TestInitialiseFetchError(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, http.StatusInternalServerError, []byte("upstream unavailable"))

	require.Error(t, c.Initialise())
}

func TestInitialiseEmptyDocumentNotCached(t *testing.T) {
	t.Parallel()

	// A list with no usable entries parses without error; caching it would blank
	// all lookups until the document TTL expires, so Initialise must fail with
	// ErrFailedToFetchData and cache nothing.
	c := newMockedClient(t, http.StatusOK, []byte("# no entries today\n"))

	err := c.Initialise()
	require.ErrorIs(t, err, providers.ErrFailedToFetchData)

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestFindHostCorruptCachedData(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "198.51.100.42")

	require.NoError(t, cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		Key:     providers.CacheProviderPrefix + ProviderName,
		Value:   []byte("not json"),
		Created: time.Now(),
	}, time.Hour))

	_, err := c.FindHost()
	require.Error(t, err)

	// the unusable document is dropped from the cache
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	require.NoError(t, err)
	require.False(t, ok)
}
