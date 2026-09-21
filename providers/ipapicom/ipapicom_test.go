package ipapicom

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

const (
	testHost    = "8.8.4.4"
	fixturePath = "testdata/ipapicom_8_8_4_4_report.json"
)

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

// newClient builds a Client over a real temp cache. With useTestData it reads
// the fixture; otherwise requests are served status and body by a mock
// transport.
func newClient(t *testing.T, useTestData bool, status int, body []byte) *Client {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	hc := retryablehttp.NewClient()
	hc.Logger = nil
	hc.RetryMax = 0
	hc.HTTPClient.Transport = mockTransport{status: status, body: body}

	sess := session.Session{
		Logger:     lg,
		Stats:      session.CreateStats(),
		Cache:      db,
		HTTPClient: hc,
	}
	sess.UseTestData = useTestData
	sess.Host = netip.MustParseAddr(testHost)

	enabled := true
	sess.Providers.IPAPICom.Enabled = &enabled

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*Client)
}

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &Client{}
	require.False(t, pc.Enabled())

	enabled := true
	pc.Providers.IPAPICom.Enabled = &enabled
	require.True(t, pc.Enabled())

	disabled := false
	pc.Providers.IPAPICom.Enabled = &disabled
	require.False(t, pc.Enabled())

	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestInitialiseRequiresCache(t *testing.T) {
	t.Parallel()

	c := newClient(t, true, http.StatusOK, nil)
	require.NoError(t, c.Initialise())

	c.Cache = nil
	require.ErrorIs(t, c.Initialise(), session.ErrCacheNotSet)
}

func TestFindHostTestDataAndTable(t *testing.T) {
	t.Parallel()

	c := newClient(t, true, http.StatusOK, nil)

	res, err := c.FindHost()
	require.NoError(t, err)

	tw, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tw)

	out := (*tw).Render()
	require.Contains(t, out, "IP-API.COM | Host: 8.8.4.4")
	require.Contains(t, out, "Ashburn")
	require.Contains(t, out, "Google Public DNS")

	ti, err := c.ExtractThreatIndicators(res)
	require.NoError(t, err)
	require.Equal(t, "US", ti.Indicators["CountryCode"])
	require.Equal(t, "true", ti.Indicators["Hosting"])
}

func TestCreateTableNoData(t *testing.T) {
	t.Parallel()

	c := newClient(t, true, http.StatusOK, nil)

	tw, err := c.CreateTable(nil)
	require.NoError(t, err)
	require.Nil(t, tw)

	tw, err = c.CreateTable([]byte(`{"status":"fail"}`))
	require.NoError(t, err)
	require.Nil(t, tw)
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newClient(t, true, http.StatusOK, nil)
	data := []byte(`{"status":"success","countryCode":"US"}`)

	res, err := c.RateHostData(data, []byte(`{"global":{"highThreatCountryCodes":["US"]}}`))
	require.NoError(t, err)
	require.True(t, res.Detected)
	require.InDelta(t, highThreatCountryScore, res.Score, 0)

	res, err = c.RateHostData(data, []byte(`{"global":{"mediumThreatCountryCodes":["US"]}}`))
	require.NoError(t, err)
	require.InDelta(t, mediumThreatCountryScore, res.Score, 0)

	res, err = c.RateHostData(data, []byte(`{"global":{}}`))
	require.NoError(t, err)
	require.False(t, res.Detected)
}

func TestFindHostNetworkSuccessThenCache(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	c := newClient(t, false, http.StatusOK, body)

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, "Ashburn", parsed.City)

	_, err = c.FindHost()
	require.NoError(t, err)
	require.True(t, c.Stats.FindHostUsedCache[ProviderName])
}

func TestFindHostNetworkPrivateRangeIsNoMatch(t *testing.T) {
	t.Parallel()

	c := newClient(t, false, http.StatusOK, []byte(`{"status":"fail","message":"private range","query":"10.0.0.1"}`))

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestFindHostNetworkFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"fail status", http.StatusOK, `{"status":"fail","message":"invalid query"}`, "invalid query"},
		{"unexpected status", http.StatusForbidden, `blocked`, "unexpected status: 403"},
		{"bad json", http.StatusOK, `boom`, "decoding ipapicom response"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := newClient(t, false, tt.status, []byte(tt.body))

			_, err := c.FindHost()
			require.Error(t, err)
			require.NotErrorIs(t, err, providers.ErrNoMatchFound)
			require.Contains(t, err.Error(), tt.want)
		})
	}
}
