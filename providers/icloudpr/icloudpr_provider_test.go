package icloudpr

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	fetcher "github.com/jonhadfield/ip-fetcher/providers/icloudpr"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

// testHostIP is an address inside the testdata prefix (172.224.224.60/31).
const testHostIP = "172.224.224.60"

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
	pc.Providers.ICloudPR.Enabled = &enabled
	require.True(t, pc.Enabled())

	// Explicitly disabled -> disabled.
	disabled := false
	pc.Providers.ICloudPR.Enabled = &disabled
	require.False(t, pc.Enabled())

	// UseTestData always enables regardless of config.
	pc.Providers.ICloudPR.Enabled = nil
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := int32(5)
	pc.Providers.ICloudPR.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	cfg := c.GetConfig()
	require.NotNil(t, cfg)
	require.True(t, cfg.UseTestData)
	require.Equal(t, netip.MustParseAddr(testHostIP), cfg.Host)
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
	require.Equal(t, netip.MustParsePrefix("172.224.224.60/31"), parsed.Prefix)
	require.Equal(t, "GB", parsed.Alpha2Code)
	require.Equal(t, "GB-WA", parsed.Region)
	require.Equal(t, "Cardiff", parsed.City)
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

	// icloudpr does not produce threat indicators; it returns nil, nil.
	indicators, err := c.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Nil(t, indicators)
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	const matchScore = 5.0

	ratingConfigJSON := `{
		"providers": {
			"icloudpr": {
				"defaultMatchScore": 5.0
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, matchScore, result.Score)
	require.Equal(t, []string{"source is iCloud Private Relay"}, result.Reasons)
}

func TestRateHostDataInvalidRatingConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	_, err = c.RateHostData(data, []byte("not-json"))
	require.Error(t, err)
}

func TestRateHostDataInvalidPrefix(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// A zero-value prefix is invalid: no error, but nothing is detected.
	findRes, err := json.Marshal(HostSearchResult{})
	require.NoError(t, err)

	result, err := c.RateHostData(findRes, []byte(`{"providers":{"icloudpr":{"defaultMatchScore":5.0}}}`))
	require.NoError(t, err)
	require.False(t, result.Detected)
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"ip_prefix":"172.224.224.60/31","alpha2code":"GB","region":"GB-WA","city":"Cardiff"}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("172.224.224.60/31"), res.Prefix)
	require.Equal(t, "GB", res.Alpha2Code)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := loadResultsFile("testdata/icloudpr_172_224_224_60_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("172.224.224.60/31"), res.Prefix)
	require.Equal(t, "Cardiff", res.City)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	// Record uses default JSON field names (Go names), as its struct tags are csv only.
	data := []byte(`{"etag":"abc","records":[{"Prefix":"172.224.224.60/31","Alpha2Code":"GB","Region":"GB-WA","City":"Cardiff"}]}`)

	doc, err := unmarshalProviderData(data)
	require.NoError(t, err)
	require.Equal(t, "abc", doc.ETag)
	require.Len(t, doc.Records, 1)
	require.Equal(t, netip.MustParsePrefix("172.224.224.60/31"), doc.Records[0].Prefix)
	require.Equal(t, "GB", doc.Records[0].Alpha2Code)
}

func TestLoadProviderDataFromCacheInvalidVersion(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// Neither is4 nor is6 -> invalid ip version error.
	_, err := c.loadProviderDataFromCache(false, false)
	require.ErrorIs(t, err, ErrInvalidIPVersion)
}

func TestSplitRecords(t *testing.T) {
	t.Parallel()

	records := []fetcher.Record{
		{Prefix: netip.MustParsePrefix("172.224.224.60/31")},
		{Prefix: netip.MustParsePrefix("2001:db8::/32")},
		{Prefix: netip.MustParsePrefix("203.0.113.0/24")},
	}

	const (
		wantFours = 2
		wantSixes = 1
	)

	fours, sixes := splitRecords(records)
	require.Len(t, fours, wantFours)
	require.Len(t, sixes, wantSixes)
	require.True(t, fours[0].Prefix.Addr().Is4())
	require.True(t, sixes[0].Prefix.Addr().Is6())
}

func TestCreateSkeletonDocs(t *testing.T) {
	t.Parallel()

	now := time.Now()
	doc := &fetcher.Doc{ETag: "etag-123", LastModified: now}

	fourDoc, sixDoc := createSkeletonDocs(doc)
	require.Equal(t, "etag-123", fourDoc.ETag)
	require.Equal(t, "etag-123", sixDoc.ETag)
	require.Equal(t, now, fourDoc.LastModified)
	require.Equal(t, now, sixDoc.LastModified)
	require.Nil(t, fourDoc.Records)
	require.Nil(t, sixDoc.Records)
}

// seedCache writes an icloudpr ipv4 Doc into the cache so the real (non-test-data)
// code paths in Initialise and FindHost run without any network access.
func seedCache(t *testing.T, c *ProviderClient, prefix netip.Prefix) {
	t.Helper()

	doc := fetcher.Doc{
		ETag: "seed-etag",
		Records: []fetcher.Record{
			{
				Prefix:     prefix,
				Alpha2Code: "GB",
				Region:     "GB-WA",
				City:       "Cardiff",
			},
		},
	}

	data, err := json.Marshal(doc)
	require.NoError(t, err)

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName + "_4",
		Value:      data,
		Version:    doc.ETag,
		Created:    time.Now(),
	}, DocTTL)
	require.NoError(t, err)
}

func TestInitialiseUsesCachedData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false

	seedCache(t, c, netip.MustParsePrefix("172.224.224.60/31"))

	// Cache already populated -> Initialise short-circuits without network.
	require.NoError(t, c.Initialise())
}

func TestFindHostFromCache(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.MustParseAddr(testHostIP)

	seedCache(t, c, netip.MustParsePrefix("172.224.224.60/31"))

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("172.224.224.60/31"), parsed.Prefix)
	require.Equal(t, "Cardiff", parsed.City)
	require.Equal(t, "seed-etag", parsed.SyncToken)
}

func TestFindHostNoMatch(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	// Host not contained in the seeded prefix.
	c.Host = netip.MustParseAddr("203.0.113.7")

	seedCache(t, c, netip.MustParsePrefix("172.224.224.60/31"))

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}
