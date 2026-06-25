package shodan

import (
	"bytes"
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
// loadAPIResponse network path can run offline against testdata.
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

// newMockedClient builds a ProviderClient wired to a mocked HTTP client and a
// real temp cache, with the provider enabled and UseTestData off so FindHost
// takes the real cache-miss -> API -> cache path.
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
	sess.Host = netip.MustParseAddr("8.8.8.8")

	enabled := true
	sess.Providers.Shodan.Enabled = &enabled
	sess.Providers.Shodan.APIKey = "test-key"

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestFindHostNetworkSuccess(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("testdata/shodan_google_dns_resp.json")
	require.NoError(t, err)

	c := newMockedClient(t, http.StatusOK, body)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, "US", parsed.CountryCode)

	// A second call should be served from the cache that the first call populated.
	cached, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, cached)
}

func TestFindHostNetworkNotFound(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, http.StatusNotFound, nil)

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestFindHostNetworkServerError(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, http.StatusInternalServerError, []byte("boom"))

	_, err := c.FindHost()
	require.Error(t, err)
	require.NotErrorIs(t, err, providers.ErrNoMatchFound)
}
