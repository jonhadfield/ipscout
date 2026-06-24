package gcp

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

// Values present in testdata/gcp_34_128_62_0_report.json.
const (
	testPrefix    = "34.128.62.0/23"
	testService   = "Google Cloud"
	testScope     = "us-west8"
	testSyncToken = "1714572299955"
	testHostIP    = "34.128.62.2"
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
	sess.Host = netip.MustParseAddr(testHostIP)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}

	// Disabled by default.
	require.False(t, pc.Enabled())

	// Enabled flag set -> enabled.
	enabled := true
	pc.Providers.GCP.Enabled = &enabled
	require.True(t, pc.Enabled())

	// Explicitly disabled -> not enabled.
	enabled = false

	require.False(t, pc.Enabled())

	// UseTestData always enables regardless of config.
	pc.Providers.GCP.Enabled = nil
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := int32(5)
	pc.Providers.GCP.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
}

func TestInitialise(t *testing.T) {
	t.Parallel()

	// Missing cache -> error.
	pc := &ProviderClient{}
	pc.Stats = session.CreateStats()
	pc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	pc.Host = netip.MustParseAddr(testHostIP)
	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.Prefix)
	require.Equal(t, testService, parsed.Service)
	require.Equal(t, testScope, parsed.Scope)
	require.Equal(t, testSyncToken, parsed.SyncToken)
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

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	indicators, err := c.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "true", indicators.Indicators["HostedInGCP"])
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	const defaultMatchScore = 5.0

	ratingConfigJSON := `{
		"providers": {
			"gcp": {
				"defaultMatchScore": 5.0
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, defaultMatchScore, result.Score)
	require.Equal(t, []string{"hosted in GCP"}, result.Reasons)
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"prefix":"192.0.2.0/24","service":"Google Cloud","scope":"us-west8"}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), res.Prefix)
	require.Equal(t, "Google Cloud", res.Service)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := loadResultsFile("testdata/gcp_34_128_62_0_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix(testPrefix), res.Prefix)
	require.Equal(t, testService, res.Service)
}
