package zscaler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/zscaler"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	// testRange is a CIDR present in the testdata fixture; used to build a
	// well-formed HostSearchResult for exercising the rating/indicator logic.
	testRange         = "147.161.174.0/23"
	testGRE           = "165.225.240.12"
	testContinent     = "EMEA"
	testCity          = "Amsterdam II"
	testDefaultScore  = 5.0
	testPriorityValue = int32(7)
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
	sess.Host = netip.MustParseAddr("147.161.174.1")

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

// validHostResultJSON returns a marshalled HostSearchResult that mirrors a real
// zscaler match, so indicator and rating logic can be exercised on the happy path.
func validHostResultJSON(t *testing.T) []byte {
	t.Helper()

	res := HostSearchResult{
		Continent: testContinent,
		City:      testCity,
		Range:     testRange,
		GRE:       testGRE,
	}

	data, err := json.Marshal(res)
	require.NoError(t, err)

	return data
}

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}

	// Disabled by default.
	require.False(t, pc.Enabled())

	// Enabled flag set -> enabled.
	enabled := true
	pc.Providers.Zscaler.Enabled = &enabled
	require.True(t, pc.Enabled())

	// Explicitly disabled.
	enabled = false
	disabled := pc.Enabled()
	require.False(t, disabled)

	// UseTestData always enables regardless of config.
	pc.Providers.Zscaler.Enabled = nil
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := testPriorityValue
	pc.Providers.Zscaler.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	require.NotNil(t, c.GetConfig())
	require.True(t, c.GetConfig().UseTestData)
}

func TestInitialiseCacheNotSet(t *testing.T) {
	t.Parallel()

	// Missing cache -> error.
	pc := &ProviderClient{}
	pc.Stats = session.CreateStats()
	pc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)
}

func TestInitialiseDataInCache(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// Pre-seed the cache so Initialise returns early without any network fetch.
	err := cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      []byte(`{"zscaler.net":{}}`),
		Created:    time.Now(),
	}, DocTTL)
	require.NoError(t, err)

	require.NoError(t, c.Initialise())
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	// The bytes returned should re-parse as a HostSearchResult.
	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.NotNil(t, parsed)
}

// seedProviderDoc loads the testdata fixture (which is in ipfetcher.Doc format),
// marshals it, and stores it in the cache exactly as loadProviderData would, so
// the real cache-backed FindHost reflection path can be exercised offline.
func seedProviderDoc(t *testing.T, c *ProviderClient) {
	t.Helper()

	raw, err := providers.LoadResultsFile[ipfetcher.Doc]("testdata/zscaler_report.json")
	require.NoError(t, err)

	data, err := json.Marshal(raw)
	require.NoError(t, err)

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, DocTTL)
	require.NoError(t, err)
}

func TestFindHostFromCache(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	seedProviderDoc(t, c)

	// 147.161.174.1 falls inside 147.161.174.0/23 (Abu Dhabi II) from the fixture.
	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Equal(t, testRange, parsed.Range)
	// FindHost derives continent/city from the ipfetcher.Doc Go field names.
	require.Equal(t, "ContinentEMEA", parsed.Continent)
	require.Equal(t, "CityAbuDhabiII", parsed.City)
}

func TestFindHostFromCacheNoMatch(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	c.UseTestData = false
	c.Host = netip.MustParseAddr("8.8.8.8")
	seedProviderDoc(t, c)

	_, err := c.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestLoadProviderDataFromCacheMissing(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// Cache has no provider doc -> read error surfaces.
	_, err := c.loadProviderDataFromCache()
	require.Error(t, err)
}

func TestLoadProviderDataFromCacheCorrupt(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// Seed the cache with invalid JSON so unmarshal fails (and the entry is purged).
	err := cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      []byte("{not-json"),
		Created:    time.Now(),
	}, DocTTL)
	require.NoError(t, err)

	_, err = c.loadProviderDataFromCache()
	require.Error(t, err)
}

func TestLoadTestData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	out, err := loadTestData(c)
	require.NoError(t, err)
	require.NotEmpty(t, out)

	_, err = unmarshalResponse(out)
	require.NoError(t, err)
}

func TestCreateTable(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	tw, err := c.CreateTable(validHostResultJSON(t))
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, testRange)
	require.Contains(t, rendered, testContinent)
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	indicators, err := c.ExtractThreatIndicators(validHostResultJSON(t))
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "true", indicators.Indicators["HostedInZscaler"])
}

func TestExtractThreatIndicatorsNoRange(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := json.Marshal(HostSearchResult{})
	require.NoError(t, err)

	_, err = c.ExtractThreatIndicators(data)
	require.Error(t, err)
}

func TestExtractThreatIndicatorsInvalidJSON(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	_, err := c.ExtractThreatIndicators([]byte("{not-json"))
	require.Error(t, err)
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	ratingConfigJSON := `{
		"providers": {
			"zscaler": {
				"defaultMatchScore": 5.0
			}
		}
	}`

	result, err := c.RateHostData(validHostResultJSON(t), []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, testDefaultScore, result.Score)
	require.Equal(t, []string{"hosted in Zscaler"}, result.Reasons)
}

func TestRateHostDataNoRange(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := json.Marshal(HostSearchResult{})
	require.NoError(t, err)

	result, err := c.RateHostData(data, []byte(`{"providers":{"zscaler":{"defaultMatchScore":5.0}}}`))
	require.Error(t, err)
	require.False(t, result.Detected)
}

func TestRateHostDataInvalidRatingConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	_, err := c.RateHostData(validHostResultJSON(t), []byte("{not-json"))
	require.Error(t, err)
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"range":"147.161.174.0/23","continent":"EMEA"}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, testRange, res.Range)
	require.Equal(t, testContinent, res.Continent)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestUnmarshalResponseInvalid(t *testing.T) {
	t.Parallel()

	_, err := unmarshalResponse([]byte("{not-json"))
	require.Error(t, err)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	raw, err := providers.LoadResultsFile[ipfetcher.Doc]("testdata/zscaler_report.json")
	require.NoError(t, err)

	data, err := json.Marshal(raw)
	require.NoError(t, err)

	doc, err := unmarshalProviderData(data)
	require.NoError(t, err)
	require.NotNil(t, doc)
}

func TestUnmarshalProviderDataInvalid(t *testing.T) {
	t.Parallel()

	_, err := unmarshalProviderData([]byte("{not-json"))
	require.Error(t, err)
}
