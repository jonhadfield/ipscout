package akamai

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

const (
	networkTestHost   = "23.32.0.5"
	networkTestPrefix = "23.32.0.0/11"
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
// upstream akamai prefix list, plus a real temp cache, with UseTestData off.
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
	sess.Host = netip.MustParseAddr(networkTestHost)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestInitialiseAndFindHostOverNetwork(t *testing.T) {
	t.Parallel()

	// upstream serves a plain-text list of prefixes, one per line
	body := []byte(networkTestPrefix + "\n104.64.0.0/10\n2600:1400::/24\n")

	c := newMockedClient(t, http.StatusOK, body)

	// Initialise on an empty cache triggers loadProviderData -> ip-fetcher Fetch,
	// served by the mock transport, then caches the parsed prefix document.
	require.NoError(t, c.Initialise())

	// FindHost reads the now-populated cache and matches the host to a prefix.
	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix(networkTestPrefix), parsed.Prefix)
}

func TestInitialiseNetworkFetchError(t *testing.T) {
	t.Parallel()

	// ip-fetcher v0.0.18 ignores the HTTP status; its Fetch fails because the
	// JSON error body cannot be parsed as a prefix-per-line list.
	c := newMockedClient(t, http.StatusServiceUnavailable, []byte(`{"error":"service unavailable"}`))

	require.Error(t, c.Initialise())
}

func TestInitialiseEmptyDocumentNotCached(t *testing.T) {
	t.Parallel()

	// An empty body parses without error in ip-fetcher v0.0.18 (zero lines ->
	// zero prefixes, nil error), so loadProviderData must reject the empty
	// document rather than cache it and blank all lookups for the TTL.
	c := newMockedClient(t, http.StatusOK, []byte(""))

	err := c.Initialise()
	require.Error(t, err)
	require.ErrorIs(t, err, providers.ErrFailedToFetchData)

	// nothing must have been cached for the provider
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	require.NoError(t, err)
	require.False(t, ok)
}
