package openai

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

// mockTransport returns a canned response per request path, so the real
// loadProviderData -> ip-fetcher Fetch network path can run offline against
// all three OpenAI bot list endpoints.
type mockTransport struct {
	status int
	bodies map[string][]byte
}

func (m mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := m.bodies[strings.TrimPrefix(req.URL.Path, "/")]

	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func mockHTTPClient(status int, bodies map[string][]byte) *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.Logger = nil
	hc.RetryMax = 0
	hc.HTTPClient.Transport = mockTransport{status: status, bodies: bodies}

	return hc
}

// newMockedClient wires a ProviderClient to a mocked HTTP client serving the
// upstream bot list fixtures, plus a real temp cache, with UseTestData off.
func newMockedClient(t *testing.T, status int, bodies map[string][]byte) *ProviderClient {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := session.Session{
		Logger:     lg,
		Stats:      session.CreateStats(),
		Cache:      db,
		HTTPClient: mockHTTPClient(status, bodies),
	}
	sess.Host = netip.MustParseAddr(testHost)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func loadListFixtures(t *testing.T) map[string][]byte {
	t.Helper()

	bodies := make(map[string][]byte)

	for _, name := range []string{"gptbot.json", "searchbot.json", "chatgpt-user.json"} {
		body, err := os.ReadFile(filepath.Join("testdata", name))
		require.NoError(t, err)

		bodies[name] = body
	}

	return bodies
}

func TestInitialiseAndFindHostOverNetwork(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, http.StatusOK, loadListFixtures(t))

	// Initialise on an empty cache triggers loadProviderData -> ip-fetcher Fetch,
	// served by the mock transport, then caches the parsed Doc.
	require.NoError(t, c.Initialise())

	// FindHost reads the now-populated cache and matches the host to a prefix.
	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Len(t, parsed.Matches, 1)
	require.Equal(t, "GPTBot", parsed.Matches[0].Name)
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Matches[0].Prefix)
}

func TestInitialiseNetworkFetchError(t *testing.T) {
	t.Parallel()

	// A non-200 response makes ip-fetcher's Fetch fail, surfacing from loadProviderData.
	c := newMockedClient(t, http.StatusInternalServerError, map[string][]byte{})

	require.Error(t, c.Initialise())
}
