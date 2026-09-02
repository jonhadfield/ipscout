package site24x7

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
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/site24x7"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	testPrefixV4 = "192.0.2.1/32"
	testPrefixV6 = "2001:db8::1/128"
)

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	enabled := true
	pc.Providers.Site24x7.Enabled = &enabled
	require.True(t, pc.Enabled())

	enabled = false
	pc.UseTestData = true
	require.True(t, pc.Enabled())

	pc.UseTestData = false
	pc.Providers.Site24x7.Enabled = nil
	require.False(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := int32(20)
	pc.Providers.Site24x7.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
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
	require.Equal(t, netip.MustParsePrefix(testPrefixV4), res.Prefix)
	require.JSONEq(t, string(data), string(res.Raw))

	_, err = unmarshalResponse([]byte(`not json`))
	require.Error(t, err)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := ipfetcher.Doc{
		IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix(testPrefixV4)},
		IPv6Prefixes: []netip.Prefix{netip.MustParsePrefix(testPrefixV6)},
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

	res, err := providers.LoadResultsFile[HostSearchResult]("testdata/site24x7_192_0_2_1_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefixV4), res.Prefix)
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix(testPrefixV4)}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	indicators, err := pc.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "true", indicators.Indicators["Site24x7Monitor"])

	empty, err := pc.ExtractThreatIndicators([]byte(`{}`))
	require.NoError(t, err)
	require.Empty(t, empty.Indicators)

	_, err = pc.ExtractThreatIndicators([]byte(`not json`))
	require.Error(t, err)
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix(testPrefixV4)}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	ratingConfigJSON := `{"providers":{"site24x7":{"defaultMatchScore":10.0}}}`

	result, err := pc.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.InEpsilon(t, 10.0, result.Score, 0.0001)
	// flat-score feeds leave Threat unset; only "noblock" is meaningful to rate/rate.go
	require.Empty(t, result.Threat)
	require.Equal(t, []string{"source is Site24x7 monitoring"}, result.Reasons)
}

func TestRateHostDataNoMatch(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}

	ratingConfigJSON := []byte(`{"providers":{"site24x7":{"defaultMatchScore":10.0}}}`)

	res, err := pc.RateHostData([]byte(`{}`), ratingConfigJSON)
	require.NoError(t, err)
	require.False(t, res.Detected)
	require.Zero(t, res.Score)

	_, err = pc.RateHostData([]byte(`not json`), ratingConfigJSON)
	require.Error(t, err)

	_, err = pc.RateHostData([]byte(`{}`), []byte(`not json`))
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

	c := newCacheSeededClient(t, "192.0.2.1")
	seedCache(t, c, ipfetcher.Doc{IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix(testPrefixV4)}})

	// cache present, so Initialise short-circuits without any network access
	require.NoError(t, c.Initialise())

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix(testPrefixV4), parsed.Prefix)

	tbl, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tbl)

	_, err = c.CreateTable([]byte(`not json`))
	require.Error(t, err)
}

func TestFindHostIPv6FromCache(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "2001:db8::1")
	seedCache(t, c, ipfetcher.Doc{IPv6Prefixes: []netip.Prefix{netip.MustParsePrefix(testPrefixV6)}})

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix(testPrefixV6), parsed.Prefix)
}

func TestFindHostNoMatch(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "203.0.113.5")
	seedCache(t, c, ipfetcher.Doc{IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix(testPrefixV4)}})

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestFindHostInvalidHost(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "192.0.2.1")
	seedCache(t, c, ipfetcher.Doc{IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix(testPrefixV4)}})
	c.Host = netip.Addr{}

	_, err := c.FindHost()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid")
}

func TestFindHostNoCache(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "192.0.2.1")

	_, err := c.FindHost()
	require.Error(t, err)
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "192.0.2.1")
	c.UseTestData = true

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix(testPrefixV4), parsed.Prefix)

	tbl, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tbl)
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

// site24x7 makes two requests: the public page, then the Zoho export URL that
// the page embeds. mockTransport returns one body for every request, so these
// tests use a transport that answers each request with the body its parser
// expects.
type site24x7Transport struct {
	status int
	page   []byte
	export []byte
}

func (t site24x7Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := t.page
	if strings.Contains(r.URL.Host, "zohopublic") {
		body = t.export
	}

	return &http.Response{
		StatusCode: t.status,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
		Request:    r,
	}, nil
}

func newSite24x7MockedClient(t *testing.T, status int, page, export []byte) *ProviderClient {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	hc := retryablehttp.NewClient()
	hc.Logger = nil
	hc.RetryMax = 0
	hc.HTTPClient.Transport = site24x7Transport{status: status, page: page, export: export}

	sess := session.Session{
		Logger:     lg,
		Stats:      session.CreateStats(),
		Cache:      db,
		HTTPClient: hc,
	}
	sess.Host = netip.MustParseAddr("192.0.2.1")

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func mockHTTPClient(status int, body []byte) *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.Logger = nil
	hc.RetryMax = 0
	hc.HTTPClient.Transport = mockTransport{status: status, body: body}

	return hc
}

// newMockedClient wires a ProviderClient to a mocked HTTP client serving the
// upstream all.txt body, plus a real temp cache, with UseTestData off.
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
	sess.Host = netip.MustParseAddr("192.0.2.1")

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestInitialiseAndFindHostOverNetwork(t *testing.T) {
	t.Parallel()

	// upstream serves JSON; this is the shape its parser expects
	c := newSite24x7MockedClient(t, http.StatusOK, []byte("<a href=\"https://creatorapp.zohopublic.com/x/y/json/z\">locations</a>"), []byte("{\"IP_Address_View\":[{\"ID\":\"1\",\"City\":\"London\",\"Place\":\"UK\",\"external_ip\":\"192.0.2.1\",\"IPv6_Address_External\":\"2001:db8::1\"}]}"))

	// Initialise on an empty cache triggers loadProviderData -> ip-fetcher Fetch,
	// served by the mock transport, then caches the parsed Doc.
	require.NoError(t, c.Initialise())

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix(testPrefixV4), parsed.Prefix)
}

func TestInitialiseNetworkFetchError(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, http.StatusInternalServerError, []byte("oops"))

	require.Error(t, c.Initialise())
}

func TestInitialiseNetworkEmptyDocument(t *testing.T) {
	t.Parallel()

	// A body carrying no usable entries parses to an empty Doc; the
	// empty-document guard must reject it rather than cache it.
	c := newSite24x7MockedClient(t, http.StatusOK, []byte("<a href=\"https://creatorapp.zohopublic.com/x/y/json/z\">locations</a>"), []byte("{}"))

	err := c.Initialise()
	require.Error(t, err)
	require.ErrorIs(t, err, providers.ErrFailedToFetchData)

	// Nothing must be cached, so the next Initialise can retry the fetch.
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestLoadProviderDataFromCacheCorrupt(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "192.0.2.1")

	require.NoError(t, cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		Key:     providers.CacheProviderPrefix + ProviderName,
		Value:   []byte("not json"),
		Created: time.Now(),
	}, time.Hour))

	_, err := c.loadProviderDataFromCache()
	require.Error(t, err)
}
