package criminalip

import (
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	// testHost is the IP address covered by the bundled test data fixture.
	testHost = "9.9.9.9"
	// scannerMatchScore is the rating applied to a scanner match in tests.
	scannerMatchScore = 7.5
	// fixturePortCount is the number of ports in the 9.9.9.9 fixture.
	fixturePortCount = 46
	// fixtureDomainCount is the number of domains in the 9.9.9.9 fixture.
	fixtureDomainCount = 72
)

// newTestClient builds a Client backed by a temporary cache and the UseTestData
// path, so the real provider logic runs without any network access.
func newTestClient(t *testing.T) *Client {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := session.Session{
		Logger: lg,
		Stats:  session.CreateStats(),
		Cache:  db,
	}
	sess.UseTestData = true
	sess.Host = netip.MustParseAddr(testHost)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*Client)
}

func TestEnabled(t *testing.T) {
	t.Parallel()

	c := &Client{}

	// Disabled by default.
	require.False(t, c.Enabled())

	// Enabled flag set but no API key -> still disabled.
	enabled := true
	c.Providers.CriminalIP.Enabled = &enabled
	require.False(t, c.Enabled())

	// Enabled flag set with API key -> enabled.
	c.Providers.CriminalIP.APIKey = "test-key"
	require.True(t, c.Enabled())

	// UseTestData always enables regardless of config.
	c.Providers.CriminalIP.Enabled = nil
	c.Providers.CriminalIP.APIKey = ""
	c.UseTestData = true
	require.True(t, c.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	c := &Client{}
	require.Nil(t, c.Priority())

	priority := int32(5)
	c.Providers.CriminalIP.OutputPriority = &priority
	require.Equal(t, priority, *c.Priority())
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	cfg := c.GetConfig()
	require.NotNil(t, cfg)
	require.Equal(t, testHost, cfg.Host.String())
}

func TestInitialise(t *testing.T) {
	t.Parallel()

	// Missing cache -> error.
	c := &Client{}
	c.Stats = session.CreateStats()
	c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	require.ErrorIs(t, c.Initialise(), session.ErrCacheNotSet)

	// Cache present -> success.
	tc := newTestClient(t)
	require.NoError(t, tc.Initialise())
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	// The returned bytes should be the raw response we can re-parse.
	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, testHost, parsed.IP)
	require.Equal(t, fixturePortCount, parsed.Port.Count)
	require.Equal(t, fixtureDomainCount, parsed.Domain.Count)
}

func TestCreateTable(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	tw, err := c.CreateTable(data)
	require.NoError(t, err)
	require.NotNil(t, tw)
	require.NotEmpty(t, (*tw).Render())
}

func TestCreateTableNilResult(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	tw, err := c.CreateTable([]byte("null"))
	require.NoError(t, err)
	require.Nil(t, tw)
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	// criminalip does not currently produce threat indicators.
	indicators, err := c.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Nil(t, indicators)
}

func TestRateHostDataNoIssues(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	// The 9.9.9.9 fixture has no flagged issues and no honeypot hits.
	ratingConfigJSON := `{
		"providers": {
			"criminalip": {
				"scannerMatchScore": 7.5
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.False(t, result.Detected)
	require.Empty(t, result.Reasons)
}

func TestRateHostDataScanner(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	// Synthetic response flagged as a scanner exercises the detection path.
	findRes := []byte(`{"ip":"9.9.9.9","issues":{"is_scanner":true}}`)

	ratingConfigJSON := `{
		"providers": {
			"criminalip": {
				"scannerMatchScore": 7.5
			}
		}
	}`

	result, err := c.RateHostData(findRes, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, scannerMatchScore, result.Score)
	require.Contains(t, result.Reasons, "scanner")
}

func TestRateHostDataInvalidRatingConfig(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	_, err := c.RateHostData([]byte(`{}`), []byte(`not-json`))
	require.Error(t, err)
}

func TestRateHostDataInvalidFindResult(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	_, err := c.RateHostData([]byte(`not-json`), []byte(`{}`))
	require.Error(t, err)
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	res, err := unmarshalResponse([]byte(`{"ip":"9.9.9.9","status":200}`))
	require.NoError(t, err)
	require.Equal(t, testHost, res.IP)
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := loadResultsFile("testdata/criminalip_9_9_9_9_report.json")
	require.NoError(t, err)
	require.Equal(t, testHost, res.IP)
	require.Equal(t, fixturePortCount, res.Port.Count)
}

func TestGenIssuesOutputForTable(t *testing.T) {
	t.Parallel()

	require.Equal(t, "none", GenIssuesOutputForTable(Issues{}))

	out := GenIssuesOutputForTable(Issues{IsScanner: true, IsVpn: true})
	require.Contains(t, out, "scanner")
	require.Contains(t, out, "VPN")
}

func TestTidyBanner(t *testing.T) {
	t.Parallel()

	// Empty lines are stripped and continuation lines are indented.
	out := tidyBanner("first\n\nsecond")
	require.Contains(t, out, "first")
	require.Contains(t, out, "second")
	require.NotContains(t, out, "\n\n")
}
