package iptoasn

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

// fixtureTSV mirrors the upstream ip2asn-combined format: IPv4 ranges sorted
// ascending, including an unrouted gap, followed by IPv6 ranges.
const fixtureTSV = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
	"8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE - Google LLC\n" +
	"10.0.0.0\t10.255.255.255\t0\tNone\tNot routed\n" +
	"2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE - Google LLC\n"

func gzipTSV(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer

	gz := gzip.NewWriter(&buf)
	_, err := gz.Write([]byte(fixtureTSV))
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	return buf.Bytes()
}

// mockTransport returns a canned response for any request, so the real
// loadProviderDataFromSource download path can run offline.
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

// mockHTTPClient builds a retryablehttp client whose transport serves the given
// status and body, with retries disabled for deterministic error-path tests.
func mockHTTPClient(status int, body []byte) *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.Logger = nil
	hc.RetryMax = 0
	hc.HTTPClient.Transport = mockTransport{status: status, body: body}

	return hc
}

// newMockedClient builds a Client wired to a mocked HTTP client and a real temp
// cache, with the provider enabled and UseTestData off so Initialise and
// FindHost take the real download -> cache -> scan path.
func newMockedClient(t *testing.T, host string, status int, body []byte) *Client {
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
	sess.Host = netip.MustParseAddr(host)

	enabled := true
	sess.Providers.IPToASN.Enabled = &enabled

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*Client)
}

func TestFindHostNetworkSuccess(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, testHost, http.StatusOK, gzipTSV(t))

	require.NoError(t, c.Initialise())

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.True(t, parsed.Announced)
	require.Equal(t, fixtureASNumber, parsed.ASNumber)
	require.Equal(t, fixtureCountryCode, parsed.ASCountryCode)
	require.Equal(t, fixtureASDescription, parsed.ASDescription)
	require.Equal(t, "8.8.8.0", parsed.FirstIP)
	require.Equal(t, "8.8.8.255", parsed.LastIP)

	require.True(t, c.Stats.FindHostUsedCache[ProviderName])
}

func TestFindHostNetworkIPv6(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, "2001:4860:4860::8888", http.StatusOK, gzipTSV(t))

	require.NoError(t, c.Initialise())

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.True(t, parsed.Announced)
	require.Equal(t, fixtureASNumber, parsed.ASNumber)
}

func TestFindHostNetworkNoMatch(t *testing.T) {
	t.Parallel()

	// 203.0.113.5 is beyond every IPv4 range in the fixture.
	c := newMockedClient(t, "203.0.113.5", http.StatusOK, gzipTSV(t))

	require.NoError(t, c.Initialise())

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestFindHostNetworkNotRouted(t *testing.T) {
	t.Parallel()

	// 10.1.2.3 falls in a "Not routed" range: no ASN details to report.
	c := newMockedClient(t, "10.1.2.3", http.StatusOK, gzipTSV(t))

	require.NoError(t, c.Initialise())

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestInitialiseDownloadError(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, testHost, http.StatusForbidden, []byte("blocked"))

	err := c.Initialise()
	require.Error(t, err)
	require.ErrorIs(t, err, providers.ErrFailedToFetchData)
}

func TestFindHostCorruptCachedData(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, testHost, http.StatusOK, []byte("not gzip"))

	require.NoError(t, c.Initialise())

	_, err := c.FindHost()
	require.Error(t, err)
	require.Contains(t, err.Error(), "decompressing iptoasn data")
}
