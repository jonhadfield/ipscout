package internetdb

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
	fixturePath = "testdata/internetdb_8_8_4_4_report.json"

	openPortsScore = 5.0
	vulnsScore     = 7.0
	ratingConfig   = `{"providers":{"internetdb":{"openPortsScore":5.0,"vulnsScore":7.0}}}`
)

type mockTransport struct {
	status int
	body   []byte
	// calls counts requests, when set
	calls *int
}

func (m mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.calls != nil {
		*m.calls++
	}

	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(bytes.NewReader(m.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func newClient(t *testing.T, useTestData bool, host string, transport mockTransport) *Client {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	hc := retryablehttp.NewClient()
	hc.Logger = nil
	hc.RetryMax = 0
	hc.HTTPClient.Transport = transport

	sess := session.Session{
		Logger:     lg,
		Stats:      session.CreateStats(),
		Cache:      db,
		HTTPClient: hc,
	}
	sess.UseTestData = useTestData
	sess.Host = netip.MustParseAddr(host)

	enabled := true
	sess.Providers.InternetDB.Enabled = &enabled

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*Client)
}

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &Client{}
	require.False(t, pc.Enabled())

	enabled := true
	pc.Providers.InternetDB.Enabled = &enabled
	require.True(t, pc.Enabled())

	pc.UseTestData = true
	pc.Providers.InternetDB.Enabled = nil
	require.True(t, pc.Enabled())
}

func TestInitialiseRequiresCache(t *testing.T) {
	t.Parallel()

	c := newClient(t, true, testHost, mockTransport{})
	require.NoError(t, c.Initialise())

	c.Cache = nil
	require.ErrorIs(t, c.Initialise(), session.ErrCacheNotSet)
}

func TestFindHostTestDataAndTable(t *testing.T) {
	t.Parallel()

	c := newClient(t, true, testHost, mockTransport{})

	res, err := c.FindHost()
	require.NoError(t, err)

	tw, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tw)

	out := (*tw).Render()
	require.Contains(t, out, "INTERNETDB | Host: 8.8.4.4")
	require.Contains(t, out, "53, 443")
	require.Contains(t, out, "dns.google")

	ti, err := c.ExtractThreatIndicators(res)
	require.NoError(t, err)
	require.Equal(t, "2", ti.Indicators["OpenPorts"])
}

func TestCreateTableNoData(t *testing.T) {
	t.Parallel()

	c := newClient(t, true, testHost, mockTransport{})

	tw, err := c.CreateTable(nil)
	require.NoError(t, err)
	require.Nil(t, tw)

	tw, err = c.CreateTable([]byte(`{"ip":"8.8.4.4","ports":[],"hostnames":[]}`))
	require.NoError(t, err)
	require.Nil(t, tw)
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newClient(t, true, testHost, mockTransport{})

	tests := []struct {
		name     string
		data     string
		detected bool
		score    float64
	}{
		{"nothing", `{"ports":[]}`, false, 0},
		{"open ports", `{"ports":[80]}`, true, openPortsScore},
		{"vulns outrank ports", `{"ports":[80],"vulns":["CVE-2024-0001"]}`, true, vulnsScore},
	}

	for _, tt := range tests {
		res, err := c.RateHostData([]byte(tt.data), []byte(ratingConfig))
		require.NoError(t, err, tt.name)
		require.Equal(t, tt.detected, res.Detected, tt.name)
		require.InDelta(t, tt.score, res.Score, 0, tt.name)
	}
}

func TestFindHostNetworkSuccessThenCache(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	var calls int

	c := newClient(t, false, testHost, mockTransport{status: http.StatusOK, body: body, calls: &calls})

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, []int{53, 443}, parsed.Ports)

	_, err = c.FindHost()
	require.NoError(t, err)
	require.True(t, c.Stats.FindHostUsedCache[ProviderName])
	require.Equal(t, 1, calls)
}

func TestFindHostNetworkNotFoundIsNoMatch(t *testing.T) {
	t.Parallel()

	c := newClient(t, false, testHost, mockTransport{status: http.StatusNotFound, body: []byte(`{"detail":"No information available"}`)})

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestFindHostSkipsNonPublicAddresses(t *testing.T) {
	t.Parallel()

	for _, host := range []string{"10.0.0.1", "192.168.1.1", "127.0.0.1", "fd00::1"} {
		var calls int

		c := newClient(t, false, host, mockTransport{status: http.StatusOK, body: []byte(`{"ports":[161]}`), calls: &calls})

		_, err := c.FindHost()
		require.ErrorIs(t, err, providers.ErrNoMatchFound, host)
		require.Zero(t, calls, host)
	}
}

func TestFindHostNetworkFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"unexpected status", http.StatusForbidden, `blocked`, "unexpected status: 403"},
		{"bad json", http.StatusOK, `boom`, "decoding internetdb response"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := newClient(t, false, testHost, mockTransport{status: tt.status, body: []byte(tt.body)})

			_, err := c.FindHost()
			require.Error(t, err)
			require.NotErrorIs(t, err, providers.ErrNoMatchFound)
			require.Contains(t, err.Error(), tt.want)
		})
	}
}
