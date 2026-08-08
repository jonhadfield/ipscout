package cloudflare

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	networkTestHost   = "104.16.132.229"
	networkTestPrefix = "104.16.0.0/13"
	// realistic upstream bodies: cloudflare serves one CIDR per line as plain text
	upstreamIPv4Body = "173.245.48.0/20\n103.21.244.0/22\n104.16.0.0/13\n"
	upstreamIPv6Body = "2400:cb00::/32\n2606:4700::/32\n"
)

// mockTransport returns canned responses for the cloudflare ips-v4/ips-v6
// endpoints, so the real loadProviderData -> ip-fetcher fetch path can run offline.
type mockTransport struct {
	status   int
	v4Body   []byte
	v6Body   []byte
	sameBody bool
}

func (m mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := m.v4Body
	if !m.sameBody && strings.Contains(req.URL.Path, "ips-v6") {
		body = m.v6Body
	}

	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func mockHTTPClient(transport mockTransport) *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.Logger = nil
	hc.RetryMax = 0
	hc.HTTPClient.Transport = transport

	return hc
}

// newMockedClient wires a ProviderClient to a mocked HTTP client plus a real
// temp cache, with UseTestData off, so Initialise exercises the network path.
func newMockedClient(t *testing.T, transport mockTransport) *ProviderClient {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := session.Session{
		Logger:     lg,
		Stats:      session.CreateStats(),
		Cache:      db,
		HTTPClient: mockHTTPClient(transport),
	}
	sess.Host = netip.MustParseAddr(networkTestHost)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestInitialiseAndFindHostOverNetwork(t *testing.T) {
	t.Parallel()

	c := newMockedClient(t, mockTransport{
		status: http.StatusOK,
		v4Body: []byte(upstreamIPv4Body),
		v6Body: []byte(upstreamIPv6Body),
	})

	// Initialise on an empty cache triggers loadProviderData -> ip-fetcher
	// FetchIPv4Data/FetchIPv6Data, served by the mock transport, then caches
	// the combined Doc.
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

	// ip-fetcher v0.0.18 ignores the HTTP status code; errors surface from
	// body parsing. A JSON error body is not a parseable CIDR list, so
	// ProcessData fails and the error surfaces from loadProviderData.
	c := newMockedClient(t, mockTransport{
		status:   http.StatusOK,
		v4Body:   []byte(`{"error":"service unavailable"}`),
		sameBody: true,
	})

	require.Error(t, c.Initialise())
}

func TestInitialiseEmptyDocumentNotCached(t *testing.T) {
	t.Parallel()

	// ip-fetcher v0.0.18 ignores the HTTP status code, so an empty body is
	// returned with a nil error and parses to zero prefixes. The empty-document
	// guard must reject it rather than cache a blank Doc for the full TTL.
	c := newMockedClient(t, mockTransport{
		status:   http.StatusOK,
		v4Body:   []byte(""),
		sameBody: true,
	})

	err := c.Initialise()
	require.Error(t, err)
	require.ErrorIs(t, err, providers.ErrFailedToFetchData)

	// nothing must have been cached for the provider
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	require.NoError(t, err)
	require.False(t, ok)
}
