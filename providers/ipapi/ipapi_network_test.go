package ipapi

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
// loadResponse network path can run offline against testdata.
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
// cache, with the provider enabled and UseTestData off so FindHost takes the
// real cache-miss -> API -> cache path.
func newMockedClient(t *testing.T, status int, body []byte) *Client {
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

	enabled := true
	sess.Providers.IPAPI.Enabled = &enabled

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*Client)
}

func TestFindHostNetworkSuccess(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("testdata/ipapi_8_8_4_4_report.json")
	require.NoError(t, err)

	c := newMockedClient(t, http.StatusOK, body)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, fixtureCountryCode, parsed.CountryCode)
	require.Equal(t, fixtureOrg, parsed.Org)

	// A second call should be served from the cache the first call populated.
	cached, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, cached)
	require.True(t, c.Stats.FindHostUsedCache[ProviderName])
}

func TestFindHostNetworkDecodeError(t *testing.T) {
	t.Parallel()

	// 200 with a non-JSON body -> decode failure in loadResponse.
	c := newMockedClient(t, http.StatusOK, []byte("boom"))

	_, err := c.FindHost()
	require.Error(t, err)
	require.Contains(t, err.Error(), "decoding ipapi response")
}

func TestFindHostNetworkRequestError(t *testing.T) {
	t.Parallel()

	// A retryable server error (500) makes the retryablehttp client give up,
	// surfacing an error from HTTPClient.Do before any body decode.
	c := newMockedClient(t, http.StatusInternalServerError, []byte("boom"))

	_, err := c.FindHost()
	require.Error(t, err)
	require.Contains(t, err.Error(), "error sending ipapi request")
}
