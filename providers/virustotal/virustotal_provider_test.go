package virustotal

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

// newTestClient builds a ProviderClient backed by a temporary cache and the
// UseTestData path, so the real provider logic runs without network access.
func newTestClient(t *testing.T) *ProviderClient {
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
	sess.Host = netip.MustParseAddr(testFixtureHost)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestEnabled(t *testing.T) {
	t.Parallel()

	c := &ProviderClient{}

	require.False(t, c.Enabled())

	c.Providers.VirusTotal.Enabled = new(true)
	require.False(t, c.Enabled())

	c.Providers.VirusTotal.APIKey = "test-key"
	require.True(t, c.Enabled())

	c.Providers.VirusTotal.Enabled = nil
	c.Providers.VirusTotal.APIKey = ""
	c.UseTestData = true
	require.True(t, c.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	c := &ProviderClient{}
	require.Nil(t, c.Priority())

	priority := int32(194)
	c.Providers.VirusTotal.OutputPriority = &priority
	require.Equal(t, priority, *c.Priority())
}

func TestInitialise(t *testing.T) {
	t.Parallel()

	c := &ProviderClient{}
	c.Stats = session.CreateStats()
	c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	c.Host = netip.MustParseAddr(testFixtureHost)
	require.ErrorIs(t, c.Initialise(), session.ErrCacheNotSet)

	tc := newTestClient(t)
	require.NoError(t, tc.Initialise())
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	parsed, err := loadFindHostResults(res)
	require.NoError(t, err)
	require.Equal(t, testFixtureHost, parsed.Data.ID)
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
	require.Equal(t, "-6", indicators.Indicators["ReputationScore"])
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	ratingConfig := []byte(`{
		"providerRatingsConfigs": {
			"virustotal": {
				"suspiciousScore": 7.6,
				"maliciousScore": 9.2
			}
		},
		"global": {
			"mediumThreatCountryCodes": ["NL"]
		}
	}`)

	result, err := c.RateHostData(data, ratingConfig)
	require.NoError(t, err)
	require.True(t, result.Score > 0)
}
