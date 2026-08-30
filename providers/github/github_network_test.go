package github

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
	networkTestHost   = "192.30.253.10"
	networkTestPrefix = "192.30.252.0/22"
)

// githubMetaBody mirrors the GitHub meta document format, including the
// non-list and non-prefix entries the real endpoint serves.
const githubMetaBody = `{
	"verifiable_password_authentication": false,
	"ssh_keys": ["ssh-ed25519 AAAA"],
	"hooks": ["192.30.252.0/22", "185.199.108.0/22"],
	"web": ["192.30.252.0/22", "185.199.108.0/22", "2606:50c0::/32"],
	"api": ["192.30.252.0/22", "2606:50c0::/32"],
	"git": ["192.30.252.0/22"],
	"pages": ["185.199.108.0/22"],
	"actions": ["4.148.0.0/16"]
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
// GitHub meta document, plus a real temp cache, with UseTestData off.
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

	c := newMockedClient(t, http.StatusOK, []byte(githubMetaBody))

	// Initialise on an empty cache triggers loadProviderData -> ip-fetcher
	// FetchData, served by the mock transport, then caches the parsed Doc.
	require.NoError(t, c.Initialise())

	// FindHost reads the now-populated cache and matches the host to a prefix.
	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix(networkTestPrefix), parsed.Prefix)
	require.Equal(t, []string{svcAPI, "git", svcHooks, svcWeb}, parsed.Services)
}

func TestInitialiseNetworkFetchError(t *testing.T) {
	t.Parallel()

	// ip-fetcher v0.0.18's FetchData returns the body regardless of HTTP
	// status; the error here comes from processData failing to parse it.
	c := newMockedClient(t, http.StatusOK, []byte("not json"))

	require.Error(t, c.Initialise())
}

func TestInitialiseEmptyDocumentNotCached(t *testing.T) {
	t.Parallel()

	// A valid JSON body with no prefix lists (e.g. an upstream error object)
	// parses cleanly, so ip-fetcher returns it with a nil error; the empty
	// document must be rejected rather than cached.
	c := newMockedClient(t, http.StatusOK, []byte(`{"verifiable_password_authentication": true, "ssh_keys": ["ssh-ed25519 AAAA"]}`))

	err := c.Initialise()
	require.Error(t, err)
	require.ErrorIs(t, err, providers.ErrFailedToFetchData)

	// nothing should have been written to the cache
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	require.NoError(t, err)
	require.False(t, ok)
}
