package ipurl

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

// mockURLTransport returns a canned response for any request, letting the real
// loadProviderURLFromSource -> ip-fetcher FetchPrefixes network path run offline.
type mockURLTransport struct {
	status int
	body   []byte
}

func (m mockURLTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(bytes.NewReader(m.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func newMockURLHTTPClient(status int, body []byte) *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.Logger = nil
	hc.RetryMax = 0
	hc.HTTPClient.Transport = mockURLTransport{status: status, body: body}

	return hc
}

// newMockedSourceClient wires a ProviderClient to a mocked HTTP client serving an
// IP list body, plus a real temp cache, with UseTestData off and an empty cache so
// the source-fetch path runs.
func newMockedSourceClient(t *testing.T, status int, body []byte) *ProviderClient {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := session.Session{
		Logger:     lg,
		Stats:      session.CreateStats(),
		Cache:      db,
		HTTPClient: newMockURLHTTPClient(status, body),
	}
	sess.Host = netip.MustParseAddr(testMatchingHost)
	sess.Providers.IPURL.URLs = []string{testURL}

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

// TestInitialiseAndFindHostOverNetwork drives the full source-fetch path:
// Initialise -> refreshURLCache -> loadProviderURLsFromSource ->
// loadProviderURLFromSource fetches the mock body, parses prefixes, caches them,
// then FindHost matches the host to the cached prefix.
func TestInitialiseAndFindHostOverNetwork(t *testing.T) {
	t.Parallel()

	// Newline-separated IP list, the format ip-fetcher's url parser expects:
	// comment lines start with '#', other lines yield a CIDR (bare IPs get /32).
	body := []byte("# test ip list\n" + testPrefixCIDR + "\n203.0.113.0/24\n")

	c := newMockedSourceClient(t, http.StatusOK, body)

	// Empty cache -> Initialise triggers the URL fetch served by the mock transport,
	// then caches the parsed prefixes for testURL.
	require.NoError(t, c.Initialise())

	// refreshURLCache must NOT have flagged the cache as already-fresh.
	c.Stats.Mu.Lock()
	usedCache := c.Stats.InitialiseUsedCache[ProviderName]
	c.Stats.Mu.Unlock()
	require.False(t, usedCache)

	// FindHost reads the now-populated cache and matches the host to the prefix.
	raw, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	result, err := unmarshalResponse(raw)
	require.NoError(t, err)

	prefix := netip.MustParsePrefix(testPrefixCIDR)
	require.Contains(t, result, prefix)
	require.Equal(t, []string{testURL}, result[prefix])
}

// TestLoadProviderURLFromSourceFetchError verifies that a non-200 response surfaces
// as an error from loadProviderURLFromSource (the per-URL fetch is otherwise
// swallowed inside the loadProviderURLsFromSource goroutine).
func TestLoadProviderURLFromSourceFetchError(t *testing.T) {
	t.Parallel()

	c := newMockedSourceClient(t, http.StatusInternalServerError, []byte("boom"))

	err := c.loadProviderURLFromSource(testURL)
	require.Error(t, err)
}

// TestLoadProviderURLFromSourceNoPrefixes verifies the empty-body branch: a 200 with
// no parseable prefixes caches nothing and returns no error.
func TestLoadProviderURLFromSourceNoPrefixes(t *testing.T) {
	t.Parallel()

	c := newMockedSourceClient(t, http.StatusOK, []byte("# only comments\n"))

	require.NoError(t, c.loadProviderURLFromSource(testURL))

	_, err := c.loadProviderURLDataFromCache(testURL)
	require.Error(t, err)
}
