package fastly

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/fastly"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	enabled := true
	pc.Providers.Fastly.Enabled = &enabled
	require.True(t, pc.Enabled())

	enabled = false
	pc.UseTestData = true
	require.True(t, pc.Enabled())

	pc.UseTestData = false
	pc.Providers.Fastly.Enabled = nil
	require.False(t, pc.Enabled())
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"prefix":"151.101.0.0/16"}`)
	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("151.101.0.0/16"), res.Prefix)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := ipfetcher.Doc{
		IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix("151.101.0.0/16")},
		IPv6Prefixes: []netip.Prefix{netip.MustParsePrefix("2a04:4e42::/32")},
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.IPv4Prefixes[0], res.IPv4Prefixes[0])
	require.Equal(t, doc.IPv6Prefixes[0], res.IPv6Prefixes[0])
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := providers.LoadResultsFile[HostSearchResult]("testdata/fastly_151_101_0_1_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("151.101.0.0/16"), res.Prefix)
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix("151.101.0.0/16")}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	indicators, err := pc.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "true", indicators.Indicators["HostedInFastly"])
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix("151.101.0.0/16")}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	ratingConfigJSON := `{"providers":{"fastly":{"defaultMatchScore":5.0}}}`

	result, err := pc.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.InEpsilon(t, 5.0, result.Score, 0.0001)
	require.Equal(t, []string{"hosted in Fastly"}, result.Reasons)
}

func newCacheSeededClient(t *testing.T, host string) *ProviderClient {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := session.Session{Logger: lg, Stats: session.CreateStats(), Cache: db}
	sess.Host = netip.MustParseAddr(host)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func seedCache(t *testing.T, c *ProviderClient, doc ipfetcher.Doc) {
	t.Helper()

	data, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		Key:     providers.CacheProviderPrefix + ProviderName,
		Value:   data,
		Created: time.Now(),
	}, time.Hour))
}

func TestInitialiseAndFindHostFromCache(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "151.101.0.5")
	seedCache(t, c, ipfetcher.Doc{IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix("151.101.0.0/16")}})

	// cache present, so Initialise short-circuits without any network access
	require.NoError(t, c.Initialise())

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("151.101.0.0/16"), parsed.Prefix)

	tbl, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tbl)
}

func TestFindHostNoMatch(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "203.0.113.5")
	seedCache(t, c, ipfetcher.Doc{IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix("151.101.0.0/16")}})

	_, err := c.FindHost()
	require.Error(t, err)
}

func TestFindHostIPv6Match(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "2a04:4e42::1")
	seedCache(t, c, ipfetcher.Doc{IPv6Prefixes: []netip.Prefix{netip.MustParsePrefix("2a04:4e42::/32")}})

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("2a04:4e42::/32"), parsed.Prefix)
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "151.101.0.1")
	c.UseTestData = true

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("151.101.0.0/16"), parsed.Prefix)
}
