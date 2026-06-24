package digitalocean

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonhadfield/ip-fetcher/providers/digitalocean"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	// testHostIP sits inside the 165.232.32.0/20 prefix held in the testdata fixture.
	testHostIP = "165.232.46.239"
	// testMatchScore is the rating score we configure and expect back.
	testMatchScore = 5.0
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
	pc.Providers.DigitalOcean.Enabled = &enabled
	require.True(t, pc.Enabled())

	// Explicitly disabled flag -> disabled.
	disabled := false
	pc.Providers.DigitalOcean.Enabled = &disabled

	require.False(t, pc.Enabled())

	// UseTestData always enables regardless of config.
	pc.Providers.DigitalOcean.Enabled = nil
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := int32(5)
	pc.Providers.DigitalOcean.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	require.NotNil(t, c.GetConfig())
	require.Equal(t, netip.MustParseAddr(testHostIP), c.GetConfig().Host)
}

func TestInitialise(t *testing.T) {
	t.Parallel()

	// Missing cache -> error.
	pc := &ProviderClient{}
	pc.Stats = session.CreateStats()
	pc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	pc.Host = netip.MustParseAddr(testHostIP)
	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)

	// Cache present (provider data pre-seeded) -> Initialise short-circuits without
	// any network fetch.
	c := newTestProviderClient(t)
	require.NoError(t, cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.Version,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      []byte(`{"records":[]}`),
		Created:    time.Now(),
	}, DocTTL))
	require.NoError(t, c.Initialise())
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	// The returned bytes should be the raw digitalocean response we can re-parse.
	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("165.232.32.0/20"), parsed.Record.Network)
	require.Equal(t, "GB", parsed.Record.CountryCode)
	require.Equal(t, "London", parsed.Record.CityName)
}

// seedProviderDoc writes a real digitalocean.Doc into the cache so the
// non-test-data FindHost path (cache load + prefix search) can run offline.
func seedProviderDoc(t *testing.T, c *ProviderClient) {
	t.Helper()

	doc := digitalocean.Doc{
		ETag: `"seed-etag"`,
		Records: []digitalocean.Record{
			{
				Network:     netip.MustParsePrefix("165.232.32.0/20"),
				NetworkText: "165.232.32.0/20",
				CountryCode: "GB",
				CityName:    "London",
			},
		},
	}

	data, err := json.Marshal(doc)
	require.NoError(t, err)

	require.NoError(t, cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.Version,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, DocTTL))
}

func TestFindHostFromCache(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false

	seedProviderDoc(t, c)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("165.232.32.0/20"), parsed.Record.Network)
	require.Equal(t, "GB", parsed.Record.CountryCode)
}

func TestFindHostNoMatch(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.MustParseAddr("8.8.8.8") // outside the seeded prefix

	seedProviderDoc(t, c)

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := digitalocean.Doc{
		ETag: `"etag"`,
		Records: []digitalocean.Record{
			{Network: netip.MustParsePrefix("165.232.32.0/20")},
		},
	}

	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.ETag, res.ETag)
	require.Equal(t, doc.Records[0].Network, res.Records[0].Network)
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
	require.Equal(t, "true", indicators.Indicators["HostedInDigitalOcean"])
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	ratingConfigJSON := `{
		"providers": {
			"digitalocean": {
				"defaultMatchScore": 5.0
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, testMatchScore, result.Score)
	require.Equal(t, []string{"hosted in DigitalOcean"}, result.Reasons)
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"prefix":{"Network":"165.232.32.0/20","CountryCode":"GB"}}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("165.232.32.0/20"), res.Record.Network)
	require.Equal(t, "GB", res.Record.CountryCode)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := loadResultsFile("testdata/digitalocean_165_232_46_239_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("165.232.32.0/20"), res.Record.Network)
	require.Equal(t, "GB", res.Record.CountryCode)
}
