package ahrefs

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
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

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
// upstream crawler-ip-ranges fixture, plus a real temp cache, with UseTestData off.
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

	body, err := os.ReadFile("testdata/crawler-ip-ranges.json")
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

	// ip-fetcher v0.0.20 never rejects on HTTP status, so an upstream error
	// page only fails when its body cannot be parsed: a 200 with an
	// unparseable body makes Fetch fail, surfacing from loadProviderData.
	c := newMockedClient(t, http.StatusOK, []byte("boom"))

	require.Error(t, c.Initialise())
}

func TestInitialiseEmptyDocumentNotCached(t *testing.T) {
	t.Parallel()

	// A valid but empty upstream document (no prefixes) parses without error;
	// caching it would blank all lookups until the document TTL expires, so
	// Initialise must fail with ErrFailedToFetchData and cache nothing.
	body := []byte(`{"prefixes":[]}`)
	c := newMockedClient(t, http.StatusOK, body)

	err := c.Initialise()
	require.Error(t, err)
	require.ErrorIs(t, err, providers.ErrFailedToFetchData)

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	require.NoError(t, err)
	require.False(t, ok)
}
