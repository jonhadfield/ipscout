package ccbot

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/ccbot"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestCCBotEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	enabled := true
	pc.Providers.CCBot.Enabled = &enabled
	require.True(t, pc.Enabled())

	enabled = false
	pc.UseTestData = true
	require.True(t, pc.Enabled())

	pc.UseTestData = false
	pc.Providers.CCBot.Enabled = nil
	require.False(t, pc.Enabled())
}

func TestCCBotUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"prefix":"192.0.2.0/24","creation_time":"2023-10-27T10:00:00Z"}`)
	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), res.Prefix)
	require.False(t, res.CreationTime.IsZero())
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestCCBotUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := ipfetcher.Doc{
		CreationTime: time.Date(2023, 10, 27, 10, 0, 0, 0, time.UTC),
		IPv4Prefixes: []ipfetcher.IPv4Entry{
			{IPv4Prefix: netip.MustParsePrefix("192.0.2.0/24")},
		},
		IPv6Prefixes: []ipfetcher.IPv6Entry{
			{IPv6Prefix: netip.MustParsePrefix("2001:db8::/32")},
		},
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.CreationTime, res.CreationTime)
	require.Equal(t, doc.IPv4Prefixes[0].IPv4Prefix, res.IPv4Prefixes[0].IPv4Prefix)
	require.Equal(t, doc.IPv6Prefixes[0].IPv6Prefix, res.IPv6Prefixes[0].IPv6Prefix)
}

func TestCCBotLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := providers.LoadResultsFile[HostSearchResult]("testdata/ccbot_192_0_2_1_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), res.Prefix)
	require.False(t, res.CreationTime.IsZero())
}

func TestCCBotExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix("192.0.2.0/24")}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	indicators, err := pc.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "true", indicators.Indicators["CCBot"])
}

func TestCCBotRateHostData(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix("192.0.2.0/24")}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	ratingConfigJSON := `{"providers":{"ccbot":{"defaultMatchScore":5.0}}}`

	result, err := pc.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.InEpsilon(t, 5.0, result.Score, 0.0001)
	require.Equal(t, []string{"source is CCBot"}, result.Reasons)
}

func newCCBotCacheSeededClient(t *testing.T, host string) *ProviderClient {
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

func seedCCBotCache(t *testing.T, c *ProviderClient, doc ipfetcher.Doc) {
	t.Helper()

	data, err := json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		Key:     providers.CacheProviderPrefix + ProviderName,
		Value:   data,
		Version: doc.CreationTime.String(),
		Created: time.Now(),
	}, time.Hour))
}

func TestCCBotInitialiseAndFindHostFromCache(t *testing.T) {
	t.Parallel()

	c := newCCBotCacheSeededClient(t, "192.0.2.5")
	seedCCBotCache(t, c, ipfetcher.Doc{
		CreationTime: time.Date(2023, 10, 27, 10, 0, 0, 0, time.UTC),
		IPv4Prefixes: []ipfetcher.IPv4Entry{
			{IPv4Prefix: netip.MustParsePrefix("192.0.2.0/24")},
		},
		IPv6Prefixes: []ipfetcher.IPv6Entry{
			{IPv6Prefix: netip.MustParsePrefix("2001:db8::/32")},
		},
	})

	// cache present, so Initialise short-circuits without any network access
	require.NoError(t, c.Initialise())

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), parsed.Prefix)
	require.False(t, parsed.CreationTime.IsZero())

	tbl, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tbl)
}

func TestCCBotFindHostNoMatch(t *testing.T) {
	t.Parallel()

	c := newCCBotCacheSeededClient(t, "203.0.113.5")
	seedCCBotCache(t, c, ipfetcher.Doc{
		IPv4Prefixes: []ipfetcher.IPv4Entry{
			{IPv4Prefix: netip.MustParsePrefix("192.0.2.0/24")},
		},
	})

	_, err := c.FindHost()
	require.Error(t, err)
}

func TestCCBotFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newCCBotCacheSeededClient(t, "192.0.2.1")
	c.UseTestData = true

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), parsed.Prefix)
	require.False(t, parsed.CreationTime.IsZero())
}
