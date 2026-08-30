package spamhaus

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	fetcherSpamhaus "github.com/jonhadfield/ip-fetcher/providers/spamhaus"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

// Values that match providers/spamhaus/testdata/spamhaus_192_0_2_5_report.json.
const (
	testHost         = "192.0.2.5"
	testPrefix       = "192.0.2.0/24"
	testSBLID        = "SBL123456"
	testRIR          = "ripencc"
	testDefaultScore = 10.0
	testTimestampRFC = "2025-02-07T16:56:00Z"
	// The IPv6 DROP list is exercised with a synthetic documentation prefix.
	testIPv6Host   = "2001:db8:1::1"
	testIPv6Prefix = "2001:db8:1::/48"
	testIPv6SBLID  = "SBL654321"
	testIPv6RIR    = "apnic"
)

func testTimestamp(t *testing.T) time.Time {
	t.Helper()

	ts, err := time.Parse(time.RFC3339, testTimestampRFC)
	require.NoError(t, err)

	return ts.UTC()
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

// seedCache writes a spamhaus provider document into the cache so that the
// non-test-data code paths (Initialise hit, loadProviderDataFromCache, FindHost
// search) can run without any network access.
func seedCache(t *testing.T, c *ProviderClient) {
	t.Helper()

	doc := fetcherSpamhaus.Doc{
		Timestamp: testTimestamp(t),
		IPv4Records: []fetcherSpamhaus.Record{
			{Prefix: netip.MustParsePrefix(testPrefix), SBLID: testSBLID, RIR: testRIR},
		},
		IPv6Records: []fetcherSpamhaus.Record{
			{Prefix: netip.MustParsePrefix(testIPv6Prefix), SBLID: testIPv6SBLID, RIR: testIPv6RIR},
		},
	}

	data, err := json.Marshal(doc)
	require.NoError(t, err)

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.Timestamp.String(),
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
	pc.Providers.Spamhaus.Enabled = &enabled
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

	priority := int32(20)
	pc.Providers.Spamhaus.OutputPriority = &priority
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
	require.Equal(t, testSBLID, parsed.SBLID)
	require.Equal(t, testRIR, parsed.RIR)
	require.False(t, parsed.Timestamp.IsZero())
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
	require.Equal(t, testSBLID, parsed.SBLID)
	require.Equal(t, testTimestamp(t), parsed.Timestamp.UTC())
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
	require.Equal(t, testIPv6SBLID, parsed.SBLID)
	require.Equal(t, testIPv6RIR, parsed.RIR)
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

func TestFindHostInvalidHost(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.Addr{}
	seedCache(t, c)

	_, err := c.FindHost()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid")
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
	require.Contains(t, rendered, testPrefix)
	require.Contains(t, rendered, testSBLID)
	require.Contains(t, rendered, testRIR)
}

func TestCreateTableMinimalResult(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false

	// A record with no SBL ID, RIR or timestamp omits those rows.
	data := []byte(`{"prefix":"` + testPrefix + `"}`)

	tw, err := c.CreateTable(data)
	require.NoError(t, err)

	rendered := (*tw).Render()
	require.Contains(t, rendered, testPrefix)
	require.NotContains(t, rendered, "SBL ID")
	require.NotContains(t, rendered, "RIR")
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
	require.Equal(t, "true", indicators.Indicators["SpamhausDROP"])
	require.Equal(t, testSBLID, indicators.Indicators["SBLID"])
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
			"spamhaus": {
				"defaultMatchScore": 10
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.InEpsilon(t, testDefaultScore, result.Score, 0.0001)
	// flat-score feeds leave Threat unset; only "noblock" is meaningful to rate/rate.go
	require.Empty(t, result.Threat)
	require.Len(t, result.Reasons, 1)
	require.Contains(t, result.Reasons[0], testSBLID)
}

func TestRateHostDataWithoutSBLID(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data := []byte(`{"prefix":"` + testPrefix + `"}`)

	ratingConfigJSON := `{"providers":{"spamhaus":{"defaultMatchScore":10}}}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Len(t, result.Reasons, 1)
	require.NotContains(t, result.Reasons[0], "SBL")
}

func TestRateHostDataNoPrefix(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// A HostSearchResult with no (invalid) prefix should not be detected.
	data := []byte(`{"timestamp":"` + testTimestampRFC + `"}`)

	ratingConfigJSON := `{"providers":{"spamhaus":{"defaultMatchScore":10}}}`

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

	data := []byte(`{"prefix":"` + testPrefix + `","sblid":"` + testSBLID + `","rir":"` + testRIR +
		`","timestamp":"` + testTimestampRFC + `"}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
	require.Equal(t, testSBLID, res.SBLID)
	require.False(t, res.Timestamp.IsZero())
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestUnmarshalResponseError(t *testing.T) {
	t.Parallel()

	_, err := unmarshalResponse([]byte("not-json"))
	require.Error(t, err)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := fetcherSpamhaus.Doc{
		Timestamp: testTimestamp(t),
		IPv4Records: []fetcherSpamhaus.Record{
			{Prefix: netip.MustParsePrefix(testPrefix), SBLID: testSBLID, RIR: testRIR},
		},
	}

	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.Timestamp, res.Timestamp)
	require.Equal(t, doc.IPv4Records[0].Prefix, res.IPv4Records[0].Prefix)
	require.Equal(t, testSBLID, res.IPv4Records[0].SBLID)
}

func TestUnmarshalProviderDataError(t *testing.T) {
	t.Parallel()

	_, err := unmarshalProviderData([]byte("not-json"))
	require.Error(t, err)
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := providers.LoadResultsFile[HostSearchResult]("testdata/spamhaus_192_0_2_5_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
	require.Equal(t, testSBLID, res.SBLID)
	require.False(t, res.Timestamp.IsZero())
}

// mockTransport serves a canned body per upstream list URL, so the real
// loadProviderData -> ip-fetcher Fetch network path can run offline.
type mockTransport struct {
	status int
	bodies map[string][]byte
}

func (m mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := m.bodies[req.URL.String()]

	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func mockHTTPClient(status int, bodies map[string][]byte) *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.Logger = nil
	hc.RetryMax = 0
	hc.HTTPClient.Transport = mockTransport{status: status, bodies: bodies}

	return hc
}

// newMockedClient wires a ProviderClient to a mocked HTTP client serving the
// upstream spamhaus lists, plus a real temp cache, with UseTestData off.
func newMockedClient(t *testing.T, status int, bodies map[string][]byte) *ProviderClient {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := session.Session{
		Logger:     lg,
		Stats:      session.CreateStats(),
		Cache:      db,
		HTTPClient: mockHTTPClient(status, bodies),
	}
	sess.Host = netip.MustParseAddr(testHost)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

// upstreamBodies returns newline delimited JSON bodies matching the upstream
// DROP list format, keyed by the URL ip-fetcher requests them from.
func upstreamBodies() map[string][]byte {
	const metadataLine = `{"type":"metadata","timestamp":1738947360,"records":1}`

	v4 := strings.Join([]string{
		`{"cidr":"` + testPrefix + `","sblid":"` + testSBLID + `","rir":"` + testRIR + `"}`,
		metadataLine,
	}, "\n")

	v6 := strings.Join([]string{
		`{"cidr":"` + testIPv6Prefix + `","sblid":"` + testIPv6SBLID + `","rir":"` + testIPv6RIR + `"}`,
		metadataLine,
	}, "\n")

	return map[string][]byte{
		fetcherSpamhaus.IPv4URL: []byte(v4),
		fetcherSpamhaus.IPv6URL: []byte(v6),
	}
}

func TestInitialiseAndFindHostOverNetwork(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, http.StatusOK, upstreamBodies())

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
	require.Equal(t, testSBLID, parsed.SBLID)
	require.Equal(t, testTimestamp(t), parsed.Timestamp.UTC())
}

func TestInitialiseNetworkFetchError(t *testing.T) {
	t.Parallel()

	// An upstream error page still returns 200 through the mock, so the failure
	// surfaces when the unparseable body is decoded as newline delimited JSON.
	bodies := map[string][]byte{
		fetcherSpamhaus.IPv4URL: []byte("boom"),
		fetcherSpamhaus.IPv6URL: []byte("boom"),
	}

	c := newMockedClient(t, http.StatusOK, bodies)

	require.Error(t, c.Initialise())
}

func TestInitialiseNetworkBadStatus(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, http.StatusInternalServerError, upstreamBodies())

	require.Error(t, c.Initialise())
}

func TestInitialiseEmptyDocumentNotCached(t *testing.T) {
	t.Parallel()

	// A valid but empty upstream document (metadata only, no records) parses
	// without error; caching it would blank all lookups until the document TTL
	// expires, so Initialise must fail with ErrFailedToFetchData and cache nothing.
	empty := []byte(`{"type":"metadata","timestamp":1738947360,"records":0}`)
	bodies := map[string][]byte{
		fetcherSpamhaus.IPv4URL: empty,
		fetcherSpamhaus.IPv6URL: empty,
	}

	c := newMockedClient(t, http.StatusOK, bodies)

	err := c.Initialise()
	require.Error(t, err)
	require.ErrorIs(t, err, providers.ErrFailedToFetchData)

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	require.NoError(t, err)
	require.False(t, ok)
}
