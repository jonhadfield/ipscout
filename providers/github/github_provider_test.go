package github

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
	svcAPI   = "api"
	svcWeb   = "web"
	svcHooks = "hooks"
)

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	enabled := true
	pc.Providers.GitHub.Enabled = &enabled
	require.True(t, pc.Enabled())

	enabled = false
	pc.UseTestData = true
	require.True(t, pc.Enabled())

	pc.UseTestData = false
	pc.Providers.GitHub.Enabled = nil
	require.False(t, pc.Enabled())
}

func TestUnmarshalResponse(t *testing.T) {
	t.Parallel()

	data := []byte(`{"prefix":"192.0.2.0/24","services":["api","web"]}`)
	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), res.Prefix)
	require.Equal(t, []string{svcAPI, svcWeb}, res.Services)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := Doc{
		Services: map[string][]netip.Prefix{
			svcAPI: {netip.MustParsePrefix("192.0.2.0/24")},
			svcWeb: {netip.MustParsePrefix("2001:db8::/32")},
		},
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.Services[svcAPI][0], res.Services[svcAPI][0])
	require.Equal(t, doc.Services[svcWeb][0], res.Services[svcWeb][0])
}

func TestProcessData(t *testing.T) {
	t.Parallel()

	// mirrors the GitHub meta document format: non-list and non-prefix
	// entries must be skipped without error
	data := []byte(`{
		"verifiable_password_authentication": true,
		"github_services_sha": "deadbeef",
		"ssh_keys": ["ssh-ed25519 AAAA"],
		"hooks": ["192.0.2.0/24"],
		"api": ["192.0.2.0/24", "2001:db8::/32"],
		"web": ["invalid-prefix"]
	}`)

	doc, err := processData(data)
	require.NoError(t, err)
	require.Len(t, doc.Services, 2)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, doc.Services[svcHooks])
	require.Len(t, doc.Services[svcAPI], 2)
	require.NotContains(t, doc.Services, svcWeb)
	require.NotContains(t, doc.Services, "ssh_keys")
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	res, err := providers.LoadResultsFile[HostSearchResult]("testdata/github_192_0_2_1_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), res.Prefix)
	require.Equal(t, []string{svcAPI, svcWeb}, res.Services)
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
	require.Equal(t, "true", indicators.Indicators["HostedInGitHub"])
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	testData := HostSearchResult{Prefix: netip.MustParsePrefix("192.0.2.0/24")}
	data, err := json.Marshal(testData)
	require.NoError(t, err)

	ratingConfigJSON := `{"providers":{"github":{"defaultMatchScore":5.0}}}`

	result, err := pc.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.InEpsilon(t, 5.0, result.Score, 0.0001)
	require.Equal(t, []string{"hosted in GitHub"}, result.Reasons)
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

func seedCache(t *testing.T, c *ProviderClient, doc Doc) {
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

	c := newCacheSeededClient(t, "192.0.2.5")
	seedCache(t, c, Doc{Services: map[string][]netip.Prefix{
		svcAPI:   {netip.MustParsePrefix("192.0.2.0/24")},
		svcHooks: {netip.MustParsePrefix("192.0.2.0/24")},
		"pages":  {netip.MustParsePrefix("203.0.113.0/24")},
	}})

	// cache present, so Initialise short-circuits without any network access
	require.NoError(t, c.Initialise())

	res, err := c.FindHost()
	require.NoError(t, err)

	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), parsed.Prefix)
	require.Equal(t, []string{svcAPI, svcHooks}, parsed.Services)

	tbl, err := c.CreateTable(res)
	require.NoError(t, err)
	require.NotNil(t, tbl)
}

func TestFindHostNoMatch(t *testing.T) {
	t.Parallel()

	c := newCacheSeededClient(t, "198.51.100.5")
	seedCache(t, c, Doc{Services: map[string][]netip.Prefix{
		svcAPI: {netip.MustParsePrefix("192.0.2.0/24")},
	}})

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
	require.Equal(t, []string{svcAPI, svcWeb}, parsed.Services)
}
