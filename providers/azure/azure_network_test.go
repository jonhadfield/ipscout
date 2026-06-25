package azure

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

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

// mockTransport returns a canned response for any request, so the real
// loadProviderDataFromSource -> ip-fetcher Fetch network path can run offline.
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
// upstream ServiceTags fixture, plus a real temp cache, with UseTestData off.
// The Azure provider URL is set so ip-fetcher skips its download-page scrape
// and fetches directly via the mocked transport.
func newMockedClient(t *testing.T, host string, status int, body []byte) *ProviderClient {
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
	sess.Providers.Azure.URL = "https://example.test/service-tags.json"

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestInitialiseAndFindHostOverNetwork(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("testdata/service_tags_network.json")
	require.NoError(t, err)

	// 4.232.106.89 is inside the fixture prefix 4.232.106.88/30.
	c := newMockedClient(t, "4.232.106.89", http.StatusOK, body)

	// Initialise on an empty cache triggers loadProviderDataFromSource ->
	// ip-fetcher Fetch, served by the mock transport, then caches the Doc.
	require.NoError(t, c.Initialise())

	// FindHost reads the now-populated cache and matches the host to a prefix.
	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("4.232.106.88/30"), parsed.Prefix)
	require.Equal(t, "ActionGroup", parsed.Name)
	require.Equal(t, "Public", parsed.Cloud)
}

func TestInitialiseNetworkFetchError(t *testing.T) {
	t.Parallel()

	// A non-200 response makes ip-fetcher's Fetch fail, surfacing from
	// loadProviderDataFromSource via Initialise.
	c := newMockedClient(t, "4.232.106.89", http.StatusInternalServerError, []byte("boom"))

	require.Error(t, c.Initialise())
}
