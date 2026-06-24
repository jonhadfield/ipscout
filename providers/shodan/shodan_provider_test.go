package shodan

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

// newTestProviderClient builds a ProviderClient backed by a temporary cache and
// the UseTestData path, so the real provider logic runs without any network access.
func newTestProviderClient(t *testing.T) *ProviderClient {
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
	sess.Host = netip.MustParseAddr("8.8.8.8")

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}

	// Disabled by default.
	require.False(t, pc.Enabled())

	// Enabled flag set but no API key -> still disabled.
	enabled := true
	pc.Providers.Shodan.Enabled = &enabled
	require.False(t, pc.Enabled())

	// Enabled flag set with API key -> enabled.
	pc.Providers.Shodan.APIKey = "test-key"
	require.True(t, pc.Enabled())

	// UseTestData always enables regardless of config.
	pc.Providers.Shodan.Enabled = nil
	pc.Providers.Shodan.APIKey = ""
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := int32(5)
	pc.Providers.Shodan.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
}

func TestInitialise(t *testing.T) {
	t.Parallel()

	// Missing cache -> error.
	pc := &ProviderClient{}
	pc.Stats = session.CreateStats()
	pc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	pc.Host = netip.MustParseAddr("8.8.8.8")
	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)

	// Cache present and host set -> success.
	c := newTestProviderClient(t)
	require.NoError(t, c.Initialise())
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	// The returned bytes should be the raw shodan response we can re-parse.
	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, "US", parsed.CountryCode)
	require.Equal(t, []int{443, 53}, parsed.Ports)
}

func TestCreateTable(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	tw, err := c.CreateTable(data)
	require.NoError(t, err)
	require.NotNil(t, tw)
	require.NotEmpty(t, (*tw).Render())
}

func TestCreateTableNilResult(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	tw, err := c.CreateTable([]byte("null"))
	require.NoError(t, err)
	require.Nil(t, tw)
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	indicators, err := c.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "2", indicators.Indicators["ExposedPorts"])
}

func TestRateHostDataOpenPorts(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	ratingConfigJSON := `{
		"providers": {
			"shodan": {
				"openPortsScore": 3.5
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, 3.5, result.Score)
	require.Contains(t, result.Reasons, "has open ports")
}

func TestRateHostDataHighThreatCountry(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	// US is the country in the fixture; flag it as high threat and ensure the
	// geolocation reason surfaces. Open-ports score is higher, so it wins on score.
	ratingConfigJSON := `{
		"global": {
			"highThreatCountryCodes": ["US"]
		},
		"providers": {
			"shodan": {
				"openPortsScore": 3.5,
				"highThreatCountryMatchScore": 1.0
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Contains(t, result.Reasons, "high Threat Country: US")
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"country_code":"US","ports":[443,53]}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, "US", res.CountryCode)
	require.Equal(t, []int{443, 53}, res.Ports)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := loadResultsFile("testdata/shodan_google_dns_resp.json")
	require.NoError(t, err)
	require.Equal(t, "US", res.CountryCode)
	require.NotEmpty(t, res.Raw)
}
