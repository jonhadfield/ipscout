package aws

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"

	ipfaws "github.com/jonhadfield/ip-fetcher/providers/aws"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

// testHost is an address contained in the testdata prefix (18.164.0.0/15).
const testHost = "18.164.52.75"

// defaultMatchScore is the score asserted for the AWS rating config.
const defaultMatchScore = 7.5

// Values present in the testdata fixture and reused across match tests.
const (
	testRegion  = "GLOBAL"
	testService = "AMAZON"
	testPrefix  = "18.164.0.0/15"
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
	sess.Host = netip.MustParseAddr(testHost)

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
	pc.Providers.AWS.Enabled = &enabled
	require.True(t, pc.Enabled())

	// Explicitly disabled -> disabled.
	disabled := false
	pc.Providers.AWS.Enabled = &disabled
	require.False(t, pc.Enabled())

	// UseTestData always enables regardless of config.
	pc.Providers.AWS.Enabled = nil
	pc.UseTestData = true
	require.True(t, pc.Enabled())
}

func TestPriority(t *testing.T) {
	t.Parallel()

	pc := &ProviderClient{}
	require.Nil(t, pc.Priority())

	priority := int32(5)
	pc.Providers.AWS.OutputPriority = &priority
	require.Equal(t, priority, *pc.Priority())
}

func TestInitialise(t *testing.T) {
	t.Parallel()

	// Missing cache -> error.
	pc := &ProviderClient{}
	pc.Stats = session.CreateStats()
	pc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	pc.Host = netip.MustParseAddr(testHost)
	require.ErrorIs(t, pc.Initialise(), session.ErrCacheNotSet)
}

func TestFindHostUsesTestData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	res, err := c.FindHost()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	// The returned bytes should be the marshalled testdata we can re-parse.
	var parsed HostSearchResult
	require.NoError(t, json.Unmarshal(res, &parsed))
	require.Equal(t, testRegion, parsed.Prefix.Region)
	require.Equal(t, testService, parsed.Prefix.Service)
	require.Equal(t, netip.MustParsePrefix(testPrefix), parsed.IPPrefix)
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
	require.Equal(t, "true", indicators.Indicators["HostedInAWS"])
}

func TestRateHostData(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	ratingConfigJSON := `{
		"providers": {
			"aws": {
				"defaultMatchScore": 7.5
			}
		}
	}`

	result, err := c.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, defaultMatchScore, result.Score)
	require.Equal(t, []string{"hosted in AWS"}, result.Reasons)
}

func TestRateHostDataInvalidRatingConfig(t *testing.T) {
	t.Parallel()

	c := newTestProviderClient(t)

	data, err := c.FindHost()
	require.NoError(t, err)

	// Malformed rating config JSON should surface an unmarshal error.
	_, err = c.RateHostData(data, []byte(`{not json`))
	require.Error(t, err)
}

func TestUnmarshalProviderData(t *testing.T) {
	t.Parallel()

	doc := ipfaws.Doc{
		SyncToken:  "1700000000",
		CreateDate: "2023-11-14-00-00-00",
		Prefixes: []ipfaws.Prefix{{
			IPPrefix: netip.MustParsePrefix(testPrefix),
			Region:   testRegion,
			Service:  testService,
		}},
	}

	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.Prefixes[0].IPPrefix, res.Prefixes[0].IPPrefix)
	require.Equal(t, testRegion, res.Prefixes[0].Region)
}

func TestMatchIPToDocIPv4(t *testing.T) {
	t.Parallel()

	doc := &ipfaws.Doc{
		Prefixes: []ipfaws.Prefix{{
			IPPrefix: netip.MustParsePrefix(testPrefix),
			Region:   testRegion,
			Service:  testService,
		}},
	}

	match, err := MatchIPToDoc(netip.MustParseAddr(testHost), doc)
	require.NoError(t, err)
	require.NotNil(t, match)
	require.Equal(t, testService, match.Prefix.Service)
	require.Equal(t, testRegion, match.Prefix.Region)
}

func TestMatchIPToDocIPv6(t *testing.T) {
	t.Parallel()

	doc := &ipfaws.Doc{
		IPv6Prefixes: []ipfaws.IPv6Prefix{{
			IPv6Prefix: netip.MustParsePrefix("2600:1f00::/24"),
			Region:     testRegion,
			Service:    testService,
		}},
	}

	match, err := MatchIPToDoc(netip.MustParseAddr("2600:1f00::1"), doc)
	require.NoError(t, err)
	require.NotNil(t, match)
	require.Equal(t, testService, match.Prefix.Service)
}

func TestMatchIPToDocNoMatch(t *testing.T) {
	t.Parallel()

	doc := &ipfaws.Doc{
		Prefixes: []ipfaws.Prefix{{
			IPPrefix: netip.MustParsePrefix(testPrefix),
		}},
	}

	_, err := MatchIPToDoc(netip.MustParseAddr("1.1.1.1"), doc)
	require.ErrorIs(t, err, providers.ErrNoMatchFound)
}
