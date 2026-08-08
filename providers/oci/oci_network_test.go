package oci

import (
	"bytes"
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

// emptyProviderDoc parses successfully via ipfetcher.Doc's custom
// UnmarshalJSON but contains no regions, so no prefixes at all
const emptyProviderDoc = `{
  "last_updated_timestamp": "2025-08-01T00:00:00.000000",
  "regions": []
}`

// mockTransport returns a canned response for any request, so the real
// loadProviderData -> ip-fetcher FetchData network path can run offline.
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
// supplied upstream body, plus a real temp cache, with UseTestData off.
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

	c := newMockedClient(t, http.StatusOK, []byte(rawProviderDoc))

	// Initialise on an empty cache triggers loadProviderData -> ip-fetcher
	// FetchData, served by the mock transport, then caches the raw document.
	require.NoError(t, c.Initialise())

	// FindHost reads the now-populated cache and matches the host to a prefix.
	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), parsed.Prefix)
	require.Equal(t, "us-ashburn-1", parsed.Region)
	require.Equal(t, []string{testTagOCI, testTagObjectStorage}, parsed.Tags)
}

func TestInitialiseNetworkFetchError(t *testing.T) {
	t.Parallel()

	// ip-fetcher v0.0.18 ignores the HTTP status: FetchData returns the body
	// with a nil error, so the failure surfaces from body parsing in
	// unmarshalProviderData rather than from the transport.
	c := newMockedClient(t, http.StatusOK, []byte("not-json"))

	require.Error(t, c.Initialise())
}

func TestInitialiseEmptyDocumentNotCached(t *testing.T) {
	t.Parallel()

	// A valid-but-empty upstream body (e.g. an error response served with a
	// non-2xx status that ip-fetcher v0.0.18 returns with a nil error) must
	// not be cached for the document TTL, as it would blank all lookups.
	c := newMockedClient(t, http.StatusOK, []byte(emptyProviderDoc))

	err := c.Initialise()
	require.Error(t, err)
	require.ErrorIs(t, err, providers.ErrFailedToFetchData)

	// nothing should have been cached
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	require.NoError(t, err)
	require.False(t, ok)
}
