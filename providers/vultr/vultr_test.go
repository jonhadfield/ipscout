package vultr

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers"
	"github.com/stretchr/testify/require"
)

func TestEnabled(t *testing.T) {
	pc := &ProviderClient{}
	enabled := true
	pc.Providers.Vultr.Enabled = &enabled
	require.True(t, pc.Enabled())

	enabled = false
	pc.UseTestData = true
	require.True(t, pc.Enabled())

	pc.UseTestData = false
	pc.Providers.Vultr.Enabled = nil
	require.False(t, pc.Enabled())
}

func TestUnmarshalResponse(t *testing.T) {
	data := []byte(`{"prefix":"192.0.2.0/24"}`)
	res, err := unmarshalResponse(data)
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), res.Prefix)
	require.JSONEq(t, string(data), string(res.Raw))
}

func TestUnmarshalProviderData(t *testing.T) {
	doc := Doc{
		IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		IPv6Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)

	res, err := unmarshalProviderData(b)
	require.NoError(t, err)
	require.Equal(t, doc.IPv4Prefixes[0], res.IPv4Prefixes[0])
	require.Equal(t, doc.IPv6Prefixes[0], res.IPv6Prefixes[0])
}

func TestLoadResultsFile(t *testing.T) {
	res, err := providers.LoadResultsFile[HostSearchResult]("testdata/vultr_192_0_2_1_report.json")
	require.NoError(t, err)
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), res.Prefix)
}

func TestExtractThreatIndicators(t *testing.T) {
	pc := &ProviderClient{}

	testData := HostSearchResult{
		Prefix: netip.MustParsePrefix("192.0.2.0/24"),
	}

	data, err := json.Marshal(testData)
	require.NoError(t, err)

	indicators, err := pc.ExtractThreatIndicators(data)
	require.NoError(t, err)
	require.Equal(t, ProviderName, indicators.Provider)
	require.Equal(t, "true", indicators.Indicators["HostedInVultr"])
}

func TestRateHostData(t *testing.T) {
	pc := &ProviderClient{}

	testData := HostSearchResult{
		Prefix: netip.MustParsePrefix("192.0.2.0/24"),
	}

	data, err := json.Marshal(testData)
	require.NoError(t, err)

	// Simple rating config JSON with just the vultr section
	ratingConfigJSON := `{
		"providers": {
			"vultr": {
				"defaultMatchScore": 5.0
			}
		}
	}`

	result, err := pc.RateHostData(data, []byte(ratingConfigJSON))
	require.NoError(t, err)
	require.True(t, result.Detected)
	require.Equal(t, 5.0, result.Score)
	require.Equal(t, []string{"hosted in Vultr"}, result.Reasons)
}
