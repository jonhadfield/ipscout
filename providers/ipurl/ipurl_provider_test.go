package ipurl

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
	testURL          = "https://example.com/ips.txt"
	testPrefixCIDR   = "5.105.62.0/24"
	testMatchingHost = "5.105.62.60"
	testNoMatchHost  = "203.0.113.1"
	testMatchScore   = 7.5
)

// newTestSession builds a session backed by a temporary BadgerDB cache so the
// real provider logic runs without any network access.
func newTestSession(t *testing.T) session.Session {
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
	sess.Host = netip.MustParseAddr(testMatchingHost)

	return sess
}

// seedURLCache writes the test prefix into the cache for testURL, the same way
// loadProviderURLFromSource does, so the cache-backed code paths run without
// hitting the network.
func seedURLCache(t *testing.T, sess session.Session, prefixes []netip.Prefix) {
	t.Helper()

	jPrefix, err := json.Marshal(prefixes)
	require.NoError(t, err)

	err = cache.UpsertWithTTL(sess.Logger, sess.Cache, cache.Item{
		AppVersion: sess.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName + "_" + generateURLHash(testURL),
		Value:      jPrefix,
		Version:    "-",
		Created:    time.Now(),
	}, CacheTTL)
	require.NoError(t, err)
}

func newTestProviderClient(t *testing.T) *ProviderClient {
	t.Helper()

	pc, err := NewProviderClient(newTestSession(t))
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestEnabled(t *testing.T) {
	pc := &ProviderClient{}

	enabled := true
	pc.Providers.IPURL.Enabled = &enabled
	require.True(t, pc.Enabled())

	enabled = false

	require.False(t, pc.Enabled())

	pc.UseTestData = true
	require.True(t, pc.Enabled())

	pc.UseTestData = false
	pc.Providers.IPURL.Enabled = nil
	require.False(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	var priority int32 = 42

	pc.Providers.IPURL.OutputPriority = &priority

	require.NotNil(t, pc.Priority())
	require.Equal(t, priority, *pc.Priority())
}

func TestGetConfig(t *testing.T) {
	sess := newTestSession(t)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	cfg := pc.GetConfig()
	require.NotNil(t, cfg)
	require.Equal(t, sess.Host, cfg.Host)
}

func TestGenerateURLHash(t *testing.T) {
	h := generateURLHash(testURL)
	require.Len(t, h, providers.CacheKeySHALen)
	// deterministic for the same input
	require.Equal(t, h, generateURLHash(testURL))
	// different input yields a different hash
	require.NotEqual(t, h, generateURLHash("https://example.com/other.txt"))
}

func TestInitialiseErrorsWhenCacheNotSet(t *testing.T) {
	pc := &ProviderClient{}
	pc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	err := pc.Initialise()
	require.ErrorIs(t, err, session.ErrCacheNotSet)
}

// TestInitialiseUsesCache verifies that Initialise (via refreshURLCache) treats
// already-cached URLs as fresh and does not attempt to fetch them.
func TestInitialiseUsesCache(t *testing.T) {
	sess := newTestSession(t)
	sess.Providers.IPURL.URLs = []string{testURL}

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	client := pc.(*ProviderClient)

	seedURLCache(t, client.Session, []netip.Prefix{netip.MustParsePrefix(testPrefixCIDR)})

	require.NoError(t, client.Initialise())

	client.Stats.Mu.Lock()
	usedCache := client.Stats.InitialiseUsedCache[ProviderName]
	client.Stats.Mu.Unlock()
	require.True(t, usedCache)
}

func TestLoadProviderURLDataFromCache(t *testing.T) {
	client := newTestProviderClient(t)

	want := []netip.Prefix{netip.MustParsePrefix(testPrefixCIDR)}
	seedURLCache(t, client.Session, want)

	got, err := client.loadProviderURLDataFromCache(testURL)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestLoadProviderURLDataFromCacheMissing(t *testing.T) {
	client := newTestProviderClient(t)

	_, err := client.loadProviderURLDataFromCache("https://example.com/never-cached.txt")
	require.Error(t, err)
}

func TestLoadProviderDataFromCache(t *testing.T) {
	client := newTestProviderClient(t)
	client.Providers.IPURL.URLs = []string{testURL}

	seedURLCache(t, client.Session, []netip.Prefix{netip.MustParsePrefix(testPrefixCIDR)})

	pwp := make(map[netip.Prefix][]string)
	require.NoError(t, client.loadProviderDataFromCache(pwp))

	prefix := netip.MustParsePrefix(testPrefixCIDR)
	require.Contains(t, pwp, prefix)
	require.Equal(t, []string{testURL}, pwp[prefix])
}

// TestFindHostMatch exercises the real FindHost cache path end-to-end: it loads
// prefixes from the seeded cache and matches the configured host.
func TestFindHostMatch(t *testing.T) {
	client := newTestProviderClient(t)
	client.Providers.IPURL.URLs = []string{testURL}
	client.Host = netip.MustParseAddr(testMatchingHost)

	seedURLCache(t, client.Session, []netip.Prefix{netip.MustParsePrefix(testPrefixCIDR)})

	raw, err := client.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	result, err := unmarshalResponse(raw)
	require.NoError(t, err)
	require.Contains(t, result, netip.MustParsePrefix(testPrefixCIDR))
	require.Equal(t, []string{testURL}, result[netip.MustParsePrefix(testPrefixCIDR)])
}

func TestFindHostNoMatch(t *testing.T) {
	client := newTestProviderClient(t)
	client.Providers.IPURL.URLs = []string{testURL}
	client.Host = netip.MustParseAddr(testNoMatchHost)

	seedURLCache(t, client.Session, []netip.Prefix{netip.MustParsePrefix(testPrefixCIDR)})

	_, err := client.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

// TestFindHostUseTestData drives the UseTestData branch of FindHost. The bundled
// fixture is a HostSearchResult map (prefix -> source URLs), so FindHost returns
// it verbatim and it re-parses to include the test prefix.
func TestFindHostUseTestData(t *testing.T) {
	client := newTestProviderClient(t)
	client.UseTestData = true

	res, err := client.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	parsed, err := unmarshalResponse(res)
	require.NoError(t, err)
	require.Contains(t, parsed, netip.MustParsePrefix(testPrefixCIDR))
}

func TestUnmarshalResponse(t *testing.T) {
	data := []byte(`{"5.105.62.0/24":["https://example.com/ips.txt"]}`)

	res, err := unmarshalResponse(data)
	require.NoError(t, err)

	prefix := netip.MustParsePrefix(testPrefixCIDR)
	require.Contains(t, res, prefix)
	require.Equal(t, []string{testURL}, res[prefix])
}

func TestUnmarshalResponseInvalid(t *testing.T) {
	_, err := unmarshalResponse([]byte(`not-json`))
	require.Error(t, err)
}

func TestCreateTable(t *testing.T) {
	client := newTestProviderClient(t)

	data, err := json.Marshal(HostSearchResult{
		netip.MustParsePrefix(testPrefixCIDR): {testURL},
	})
	require.NoError(t, err)

	tw, err := client.CreateTable(data)
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.Contains(t, rendered, testPrefixCIDR)
	require.Contains(t, rendered, testURL)
}

func TestCreateTableEmpty(t *testing.T) {
	client := newTestProviderClient(t)

	data, err := json.Marshal(HostSearchResult{})
	require.NoError(t, err)

	tw, err := client.CreateTable(data)
	require.NoError(t, err)
	require.NotNil(t, tw)
}

func TestCreateTableInvalid(t *testing.T) {
	client := newTestProviderClient(t)

	_, err := client.CreateTable([]byte(`not-json`))
	require.Error(t, err)
}

func TestExtractThreatIndicators(t *testing.T) {
	client := newTestProviderClient(t)

	indicators, err := client.ExtractThreatIndicators([]byte(`{}`))
	require.NoError(t, err)
	require.Nil(t, indicators)
}

func TestRateHostDataDetected(t *testing.T) {
	client := newTestProviderClient(t)

	findRes, err := json.Marshal(HostSearchResult{
		netip.MustParsePrefix(testPrefixCIDR): {testURL},
	})
	require.NoError(t, err)

	ratingConfigJSON := []byte(`{
		"providers": {
			"ipurl": {
				"defaultMatchScore": 7.5
			}
		}
	}`)

	result, err := client.RateHostData(findRes, ratingConfigJSON)
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, testMatchScore, result.Score)
	require.Len(t, result.Reasons, 1)
	require.Contains(t, result.Reasons[0], "matched prefix in 1 ip sets")
}

func TestRateHostDataNotDetected(t *testing.T) {
	client := newTestProviderClient(t)

	findRes, err := json.Marshal(HostSearchResult{})
	require.NoError(t, err)

	result, err := client.RateHostData(findRes, []byte(`{"providers":{"ipurl":{"defaultMatchScore":7.5}}}`))
	require.NoError(t, err)
	require.False(t, result.Detected)
	require.Zero(t, result.Score)
	require.Empty(t, result.Reasons)
}

func TestRateHostDataInvalidRatingConfig(t *testing.T) {
	client := newTestProviderClient(t)

	_, err := client.RateHostData([]byte(`{}`), []byte(`not-json`))
	require.Error(t, err)
}

func TestRateHostDataInvalidFindResult(t *testing.T) {
	client := newTestProviderClient(t)

	_, err := client.RateHostData([]byte(`not-json`), []byte(`{"providers":{"ipurl":{"defaultMatchScore":7.5}}}`))
	require.Error(t, err)
}
