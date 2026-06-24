package abuseipdb

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

// testHost is the IP address covered by the bundled testdata fixture.
const testHost = "194.169.175.35"

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

	pc, err := NewClient(sess)
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
	c.Providers.AbuseIPDB.Enabled = &enabled
	require.False(t, c.Enabled())

	// Enabled flag set with API key -> enabled.
	c.Providers.AbuseIPDB.APIKey = "test-key"
	require.True(t, c.Enabled())

	// UseTestData always enables regardless of config.
	c.Providers.AbuseIPDB.Enabled = nil
	c.Providers.AbuseIPDB.APIKey = ""
	c.UseTestData = true
	require.True(t, c.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	c := &Client{}
	require.Nil(t, c.Priority())

	priority := int32(OutputPriority)
	c.Providers.AbuseIPDB.OutputPriority = &priority
	require.Equal(t, priority, *c.Priority())
}

func TestInitialise(t *testing.T) {
	t.Parallel()

	// Missing cache -> error.
	c := &Client{}
	c.Stats = session.CreateStats()
	c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	c.Host = netip.MustParseAddr(testHost)
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
	require.Equal(t, testHost, parsed.Data.IPAddress)
	require.Equal(t, "Bulgaria", parsed.Data.CountryName)
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

	indicators, err := c.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	// abuseConfidenceScore in the fixture is 100.
	require.Equal(t, "100", indicators.Indicators["AbuseConfidencePercentage"])
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	result, err := c.RateHostData(data, []byte(`{}`))
	require.NoError(t, err)
	require.True(t, result.Detected)
	// confidence 100 / abuseScoreMultiplier (10) = 10 -> capped at veryHighScoreThreshold.
	require.InDelta(t, float64(veryHighScoreThreshold), result.Score, 0)
	require.Equal(t, "very high", result.Threat)
	require.Contains(t, result.Reasons, "confidence: 100.00")
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"data":{"ipAddress":"194.169.175.35","countryName":"Bulgaria"}}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, testHost, res.Data.IPAddress)
	require.Equal(t, "Bulgaria", res.Data.CountryName)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := loadResultsFile("testdata/abuseipdb_194_169_175_35_report.json")
	require.NoError(t, err)
	require.Equal(t, testHost, res.Data.IPAddress)
}
