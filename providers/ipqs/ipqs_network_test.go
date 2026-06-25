package ipqs

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
func newMockedClient(t *testing.T, body []byte) *Client {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := session.Session{
		Logger:     lg,
		Stats:      session.CreateStats(),
		Cache:      db,
		HTTPClient: mockHTTPClient(http.StatusOK, body),
	}
	sess.Host = netip.MustParseAddr("74.125.219.32")

	enabled := true
	sess.Providers.IPQS.Enabled = &enabled
	sess.Providers.IPQS.APIKey = "test-key"

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*Client)
}

func TestFindHostNetworkSuccess(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("testdata/ipqs_74_125_219_32_report.json")
	require.NoError(t, err)

	c := newMockedClient(t, body)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	var parsed ipqsResp
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, "US", parsed.CountryCode)
	require.Equal(t, 75, parsed.FraudScore)

	// A second call should be served from the cache that the first call populated.
	cached, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, cached)
}

func TestFindHostNetworkUnsuccessfulResponse(t *testing.T) {
	t.Parallel()

	// IPQS signals failure via success=false in the JSON body, not the status code.
	body := []byte(`{"success":false,"message":"Invalid or unauthorized key."}`)

	c := newMockedClient(t, body)

	_, err := c.FindHost()
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid or unauthorized key.")
}

func TestFindHostNetworkEmptyBody(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, nil)

	_, err := c.FindHost()
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty")
}

func TestFindHostNetworkInvalidJSON(t *testing.T) {
	t.Parallel()

	// 200 with a non-JSON body drives the json.Unmarshal decode-error path.
	c := newMockedClient(t, []byte("not json"))

	_, err := c.FindHost()
	require.Error(t, err)
	require.Contains(t, err.Error(), "decoding")
}
