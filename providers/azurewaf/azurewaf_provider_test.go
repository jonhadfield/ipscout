package azurewaf

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

// testHost is an address contained within the prefixes in the testdata fixture
// (165.232.46.0/24 and 165.232.46.239/32).
const testHost = "165.232.46.239"

// rulePriority is used for the seeded custom rule in the cache-backed match test.
const rulePriority int32 = 100

func ptr[T any](v T) *T { return &v }

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
	sess.Host = netip.MustParseAddr(testHost)

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	return pc.(*ProviderClient)
}

func TestEnabled(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}

	// Disabled by default (Enabled flag nil, no test data).
	require.False(t, pc.Enabled())

	// Enabled flag explicitly true -> enabled.
	enabled := true
	pc.Providers.AzureWAF.Enabled = &enabled
	require.True(t, pc.Enabled())

	// Enabled flag explicitly false -> disabled.
	enabled = false

	require.False(t, pc.Enabled())

	// UseTestData always enables regardless of config.
	pc.Providers.AzureWAF.Enabled = nil
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := int32(7)
	pc.Providers.AzureWAF.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
}

func TestInitialiseCacheNotSet(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	pc.Stats = session.CreateStats()
	pc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	pc.Host = netip.MustParseAddr(testHost)

	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)
}

func TestInitialiseSuccess(t *testing.T) {
	t.Parallel()

	// With a cache present and no resource IDs configured, Initialise loads an
	// empty policy set into the cache without any network access.
	c := newTestProviderClient(t)
	require.NoError(t, c.Initialise())

	// A second call should find the data already cached and succeed.
	require.NoError(t, c.Initialise())
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	// The returned bytes should be the fixture, re-parseable as a HostSearchResult.
	doc, err := loadResultsFile(c.Logger, "testdata/azurewaf_report.json")
	require.NoError(t, err)
	require.Len(t, doc.PolicyMatches, 1)
	require.Equal(t, "Group1", doc.PolicyMatches[0].RID.ResourceGroup)
	require.Equal(t, "Policy1", doc.PolicyMatches[0].RID.Name)
	require.Len(t, doc.PolicyMatches[0].CustomRuleMatches, 2)
	require.Equal(t, "Rule1", doc.PolicyMatches[0].CustomRuleMatches[0].RuleName)
	require.Equal(t, netip.MustParsePrefix("165.232.46.0/24"), doc.PolicyMatches[0].CustomRuleMatches[0].Prefixes[0])
}

// TestFindHostFromCacheMatches exercises the non-test-data path: it seeds the
// cache with a real armfrontdoor policy whose custom rule contains the host's
// prefix, then drives FindHost so loadProviderDataFromCache and
// matchIPToPolicyCustomRules run against real data.
func TestFindHostFromCacheMatches(t *testing.T) {
	t.Parallel()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	policy := &armfrontdoor.WebApplicationFirewallPolicy{
		ID:   ptr("/subscriptions/sub-1/resourcegroups/rg-1/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/pol-1"),
		Name: ptr("pol-1"),
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			CustomRules: &armfrontdoor.CustomRuleList{
				Rules: []*armfrontdoor.CustomRule{
					{
						Name:     ptr("BlockRule"),
						Action:   ptr(armfrontdoor.ActionTypeBlock),
						Priority: ptr(rulePriority),
						RuleType: ptr(armfrontdoor.RuleTypeMatchRule),
						MatchConditions: []*armfrontdoor.MatchCondition{
							{
								MatchVariable:   ptr(armfrontdoor.MatchVariableRemoteAddr),
								Operator:        ptr(armfrontdoor.OperatorIPMatch),
								NegateCondition: ptr(false),
								MatchValue:      []*string{ptr("165.232.46.0/24")},
							},
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal([]*armfrontdoor.WebApplicationFirewallPolicy{policy})
	require.NoError(t, err)

	sess := session.Session{Logger: lg, Stats: session.CreateStats(), Cache: db}
	sess.Host = netip.MustParseAddr(testHost)
	sess.App.SemVer = "test"

	require.NoError(t, cache.UpsertWithTTL(lg, db, cache.Item{
		AppVersion: sess.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, DocTTL))

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	res, err := pc.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	var result HostSearchResult
	require.NoError(t, json.Unmarshal(res, &result))
	require.Len(t, result.PolicyMatches, 1)
	require.Equal(t, "rg-1", result.PolicyMatches[0].RID.ResourceGroup)
	require.Len(t, result.PolicyMatches[0].CustomRuleMatches, 1)
	require.Equal(t, "BlockRule", result.PolicyMatches[0].CustomRuleMatches[0].RuleName)
	require.Equal(t, "Block", result.PolicyMatches[0].CustomRuleMatches[0].Action)
}

// TestFindHostFromCacheNoMatch drives the non-test-data path where the host is
// not contained in any policy prefix, returning ErrNoMatchFound.
func TestFindHostFromCacheNoMatch(t *testing.T) {
	t.Parallel()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	db, err := cache.Create(lg, filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	policy := &armfrontdoor.WebApplicationFirewallPolicy{
		ID:   ptr("/subscriptions/sub-1/resourcegroups/rg-1/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/pol-1"),
		Name: ptr("pol-1"),
		Properties: &armfrontdoor.WebApplicationFirewallPolicyProperties{
			CustomRules: &armfrontdoor.CustomRuleList{
				Rules: []*armfrontdoor.CustomRule{
					{
						Name:     ptr("BlockRule"),
						Action:   ptr(armfrontdoor.ActionTypeBlock),
						Priority: ptr(rulePriority),
						RuleType: ptr(armfrontdoor.RuleTypeMatchRule),
						MatchConditions: []*armfrontdoor.MatchCondition{
							{
								MatchVariable:   ptr(armfrontdoor.MatchVariableRemoteAddr),
								Operator:        ptr(armfrontdoor.OperatorIPMatch),
								NegateCondition: ptr(false),
								MatchValue:      []*string{ptr("10.0.0.0/24")},
							},
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal([]*armfrontdoor.WebApplicationFirewallPolicy{policy})
	require.NoError(t, err)

	sess := session.Session{Logger: lg, Stats: session.CreateStats(), Cache: db}
	sess.Host = netip.MustParseAddr(testHost)
	sess.App.SemVer = "test"

	require.NoError(t, cache.UpsertWithTTL(lg, db, cache.Item{
		AppVersion: sess.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, DocTTL))

	pc, err := NewProviderClient(sess)
	require.NoError(t, err)

	_, err = pc.FindHost()
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}

func TestCreateTable(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	tw, err := c.CreateTable(data)
	require.NoError(t, err)
	require.NotNil(t, tw)

	rendered := (*tw).Render()
	require.NotEmpty(t, rendered)
	require.Contains(t, rendered, "Rule1")
	require.Contains(t, rendered, "Group1")
}

func TestCreateTableNoMatch(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	// An empty result set unmarshals cleanly and yields a table with no policy rows.
	tw, err := c.CreateTable([]byte("null"))
	require.NoError(t, err)
	require.NotNil(t, tw)
}

func TestExtractThreatIndicators(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	// azurewaf does not currently emit threat indicators.
	indicators, err := c.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Nil(t, indicators)
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	// azurewaf does not currently contribute to rating.
	result, err := c.RateHostData(data, []byte(`{}`))
	require.NoError(t, err)
	require.Equal(t, providers.RateResult{}, result)
}

func TestLoadResultsFile(t *testing.T) {
	t.Parallel()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	res, err := loadResultsFile(lg, "testdata/azurewaf_report.json")
	require.NoError(t, err)
	require.Len(t, res.PolicyMatches, 1)
	require.Equal(t, "f505ff0d-1bb2-4f5a-a6d0-214887b9faeb", res.PolicyMatches[0].RID.SubscriptionID)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	// Empty JSON array unmarshals to an empty policy slice without error.
	res, err := unmarshalProviderData([]byte("[]"))
	require.NoError(t, err)
	require.Empty(t, res)
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)
	require.NotNil(t, c.GetConfig())
	require.True(t, c.GetConfig().UseTestData)
}
