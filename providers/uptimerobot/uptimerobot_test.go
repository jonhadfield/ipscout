package uptimerobot

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
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/uptimerobot"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	testHost     = "192.0.2.1"
	testPrefix   = "192.0.2.1/32"
	testV6Host   = "2001:db8::1"
	testV6Prefix = "2001:db8::1/128"
)

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	enabled := true
	pc.Providers.UptimeRobot.Enabled = &enabled
	require.True(t, pc.Enabled())

	enabled = false
	pc.UseTestData = true
	require.True(t, pc.Enabled())

	pc.UseTestData = false
	pc.Providers.UptimeRobot.Enabled = nil
	require.False(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := int32(60)
	pc.Providers.UptimeRobot.OutputPriority = &priority
	require.Equal(t, &priority, pc.Priority())
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Equal(t, &pc.Session, pc.GetConfig())
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"prefix":"192.0.2.1/32"}`)
	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
	require.JSONEq(t, string(data), string(res.Raw))

	_, err = unmarshalResponse([]byte("not json"))
	require.Error(t, err)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := ipfetcher.Doc{
		IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix(testPrefix)},
		IPv6Prefixes: []netip.Prefix{netip.MustParsePrefix(testV6Prefix)},
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.IPv4Prefixes[0], res.IPv4Prefixes[0])
	require.Equal(t, doc.IPv6Prefixes[0], res.IPv6Prefixes[0])

	_, err = unmarshalProviderData([]byte("not json"))
	require.Error(t, err)
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := providers.LoadResultsFile[HostSearchResult]("testdata/uptimerobot_192_0_2_1_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix(testPrefix)}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	indicators, err := pc.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "true", indicators.Indicators["UptimeRobotMonitor"])

	_, err = pc.ExtractThreatIndicators([]byte("not json"))
	require.Error(t, err)
}

func TestExtractThreatIndicatorsNoMatch(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	data, err := json.Marshal(HostSearchResult{})
	require.NoError(t, err)

	indicators, err := pc.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Empty(t, indicators.Indicators)
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix(testPrefix)}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	ratingConfigJSON := `{"providers":{"uptimerobot":{"defaultMatchScore":1.0}}}`

	result, err := pc.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.InEpsilon(t, 1.0, result.Score, 0.0001)
	require.Equal(t, []string{"source is UptimeRobot monitoring"}, result.Reasons)
}

func TestRateHostDataErrors(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	ratingConfigJSON := []byte(`{"providers":{"uptimerobot":{"defaultMatchScore":1.0}}}`)

	_, err := pc.RateHostData([]byte("{}"), []byte("not json"))
	require.Error(t, err)

	_, err = pc.RateHostData([]byte("not json"), ratingConfigJSON)
	require.Error(t, err)

	data, err := json.Marshal(HostSearchResult{})
	require.NoError(t, err)

	res, err := pc.RateHostData(data, ratingConfigJSON)
	require.NoError(t, err)
	require.False(t, res.Detected)
	require.Zero(t, res.Score)
}

func newTestClient(t *testing.T, host string) *ProviderClient {
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

func TestInitialiseAndFindHostFromCache(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, testHost)
	seedCache(t, c, ipfetcher.Doc{IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix(testPrefix)}})

	// cache present, so Initialise short-circuits without any network access
	require.NoError(t, c.Initialise())

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Prefix)

	tbl, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tbl)
}

func TestFindHostMatchesIPv6(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, testV6Host)
	seedCache(t, c, ipfetcher.Doc{
		IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix(testPrefix)},
		IPv6Prefixes: []netip.Prefix{netip.MustParsePrefix(testV6Prefix)},
	})

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix(testV6Prefix), parsed.Prefix)
}

func TestFindHostNoMatch(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, "203.0.113.5")
	seedCache(t, c, ipfetcher.Doc{IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix(testPrefix)}})

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestFindHostCorruptCache(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, testHost)
	require.NoError(t, cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		Key:     providers.CacheProviderPrefix + ProviderName,
		Value:   []byte("not json"),
		Created: time.Now(),
	}, time.Hour))

	_, err := c.FindHost()
	require.Error(t, err)
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, testHost)
	c.UseTestData = true

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Prefix)

	tbl, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tbl)
}

func TestCreateTableError(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, testHost)

	_, err := c.CreateTable([]byte("not json"))
	require.Error(t, err)
}

func TestInitialiseWithoutCache(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)
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
// upstream uptimerobot address list, plus a real temp cache, with UseTestData off.
func newMockedClient(t *testing.T, status int, body []byte) *ProviderClient {
	t.Helper()

	c := newTestClient(t, testHost)
	c.HTTPClient = mockHTTPClient(status, body)

	return c
}

func TestInitialiseAndFindHostOverNetwork(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, http.StatusOK, []byte(testHost+"\n"+testV6Host+"\n"))

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

	c := newMockedClient(t, http.StatusInternalServerError, []byte("boom"))

	require.Error(t, c.Initialise())
}

func TestInitialiseEmptyDocumentNotCached(t *testing.T) {
	t.Parallel()

	// Unparseable entries are skipped upstream, yielding a valid but empty
	// document; caching it would blank all lookups until the document TTL
	// expires, so Initialise must fail with ErrFailedToFetchData and cache nothing.
	c := newMockedClient(t, http.StatusOK, []byte("not-an-address\n"))

	err := c.Initialise()
	require.Error(t, err)
	require.ErrorIs(t, err, providers.ErrFailedToFetchData)

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestDocumentCacheTTLOverride(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, http.StatusOK, []byte(testHost+"\n"))
	c.Providers.UptimeRobot.DocumentCacheTTL = 1

	require.NoError(t, c.Initialise())

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	require.NoError(t, err)
	require.True(t, ok)
}
