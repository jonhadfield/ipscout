package oci

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	testTagOCI           = "OCI"
	testTagObjectStorage = "OBJECT_STORAGE"
)

// rawProviderDoc is oci data in the source format expected by
// ipfetcher.Doc's custom UnmarshalJSON, with 192.0.2.1 inside 192.0.2.0/24
const rawProviderDoc = `{
  "last_updated_timestamp": "2025-08-01T00:00:00.000000",
  "regions": [
    {
      "region": "us-ashburn-1",
      "cidrs": [
        {
          "cidr": "192.0.2.0/24",
          "tags": ["OCI", "OBJECT_STORAGE"]
        }
      ]
    }
  ]
}`

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	enabled := true
	pc.Providers.OCI.Enabled = &enabled
	require.True(t, pc.Enabled())

	enabled = false
	pc.UseTestData = true
	require.True(t, pc.Enabled())

	pc.UseTestData = false
	pc.Providers.OCI.Enabled = nil
	require.False(t, pc.Enabled())
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"prefix":"192.0.2.0/24","region":"us-ashburn-1","tags":["OCI"]}`)
	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), res.Prefix)
	require.Equal(t, "us-ashburn-1", res.Region)
	require.Equal(t, []string{testTagOCI}, res.Tags)
	require.Equal(t, data, res.Raw)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	res, err := unmarshalProviderData([]byte(rawProviderDoc))
	require.NoError(t, err)
	require.Len(t, res.Regions, 1)
	require.Equal(t, "us-ashburn-1", res.Regions[0].Region)
	require.Len(t, res.Regions[0].CIDRS, 1)
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), res.Regions[0].CIDRS[0].CIDR)
	require.Equal(t, []string{testTagOCI, testTagObjectStorage}, res.Regions[0].CIDRS[0].Tags)
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := providers.LoadResultsFile[HostSearchResult]("testdata/oci_192_0_2_1_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), res.Prefix)
	require.Equal(t, "us-ashburn-1", res.Region)
	require.Equal(t, []string{testTagOCI, testTagObjectStorage}, res.Tags)
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix("192.0.2.0/24")}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	indicators, err := pc.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "true", indicators.Indicators["HostedInOCI"])
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix("192.0.2.0/24")}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	ratingConfigJSON := `{"providers":{"oci":{"defaultMatchScore":5.0}}}`

	result, err := pc.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.InEpsilon(t, 5.0, result.Score, 0.0001)
	require.Equal(t, []string{"hosted in Oracle Cloud (OCI)"}, result.Reasons)
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

func seedCache(t *testing.T, c *ProviderClient, data []byte) {
	t.Helper()

	require.NoError(t, cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		Key:     providers.CacheProviderPrefix + ProviderName,
		Value:   data,
		Created: time.Now(),
	}, time.Hour))
}

func TestInitialiseAndFindHostFromCache(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "192.0.2.5")
	seedCache(t, c, []byte(rawProviderDoc))

	// cache present, so Initialise short-circuits without any network access
	require.NoError(t, c.Initialise())

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), parsed.Prefix)
	require.Equal(t, "us-ashburn-1", parsed.Region)
	require.Equal(t, []string{testTagOCI, testTagObjectStorage}, parsed.Tags)

	tbl, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tbl)
}

func TestFindHostNoMatch(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "203.0.113.5")
	seedCache(t, c, []byte(rawProviderDoc))

	_, err := c.FindHost()
	require.Error(t, err)
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "192.0.2.1")
	c.UseTestData = true

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), parsed.Prefix)
	require.Equal(t, "us-ashburn-1", parsed.Region)
}
