package ipapi

import (
	"encoding/json"
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
	testHost                 = "8.8.4.4"
	fixtureCountryCode       = "US"
	fixtureCountryCodeISO3   = "USA"
	fixtureOrg               = "GOOGLE"
	highThreatCountryScore   = 9.0
	mediumThreatCountryScore = 7.0
)

// newTestProviderClient builds a ProviderClient backed by a temporary cache and
// the UseTestData path, so the real provider logic runs without any network access.
func newTestProviderClient(t *testing.T) *Client {
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

	pc := &Client{}

	// Disabled by default.
	require.False(t, pc.Enabled())

	// Enabled flag set -> enabled.
	enabled := true
	pc.Providers.IPAPI.Enabled = &enabled
	require.True(t, pc.Enabled())

	// Explicitly disabled.
	disabled := false
	pc.Providers.IPAPI.Enabled = &disabled
	require.False(t, pc.Enabled())

	// UseTestData always enables regardless of config.
	pc.Providers.IPAPI.Enabled = nil
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &Client{}
	require.Nil(t, pc.Priority())

	priority := int32(5)
	pc.Providers.IPAPI.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
}

func TestInitialise(t *testing.T) {
	t.Parallel()

	// Missing cache -> error.
	pc := &Client{}
	pc.Stats = session.CreateStats()
	pc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	pc.Host = netip.MustParseAddr(testHost)
	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)

	// Cache present -> success.
	c := newTestProviderClient(t)
	require.NoError(t, c.Initialise())
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	cfg := c.GetConfig()
	require.NotNil(t, cfg)
	require.True(t, cfg.UseTestData)
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, fixtureCountryCode, parsed.CountryCode)
	require.Equal(t, fixtureOrg, parsed.Org)
	require.Equal(t, testHost, parsed.IP)
}

func TestCreateTable(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	tw, err := c.CreateTable(data)
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, fixtureOrg)
}

func TestCreateTableNilData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	tw, err := c.CreateTable(nil)
	require.NoError(t, err)
	require.Nil(t, tw)
}

func TestCreateTableNoLocationData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// Empty region and zero lat/long -> nothing to render.
	tw, err := c.CreateTable([]byte(`{"country_code":"US"}`))
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
	require.Equal(t, fixtureCountryCodeISO3, indicators.Indicators["CountryCodeISO3"])
}

func TestRateHostDataHighThreatCountry(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	// US is the country in the fixture; flag it as high threat.
	ratingConfigJSON := `{
		"global": {
			"highThreatCountryCodes": ["US"]
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, highThreatCountryScore, result.Score)
	require.Contains(t, result.Reasons, "High Threat Country: US")
}

func TestRateHostDataMediumThreatCountry(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	// US is the country in the fixture; flag it as medium threat.
	ratingConfigJSON := `{
		"global": {
			"mediumThreatCountryCodes": ["US"]
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, mediumThreatCountryScore, result.Score)
	require.Contains(t, result.Reasons, "Medium Threat Country: US")
}

func TestRateHostDataNoMatch(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	// No country codes flagged -> not detected.
	result, err := c.RateHostData(data, []byte(`{"global":{}}`))
	require.NoError(t, err)
	require.False(t, result.Detected)
	require.Zero(t, result.Score)
	require.Empty(t, result.Reasons)
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := loadResultsFile("testdata/ipapi_8_8_4_4_report.json")
	require.NoError(t, err)
	require.Equal(t, fixtureCountryCode, res.CountryCode)
	require.Equal(t, fixtureOrg, res.Org)
}
