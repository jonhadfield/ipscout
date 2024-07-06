package ipqs

import (
	"testing"

	"github.com/jonhadfield/ipscout/providers"
	"github.com/stretchr/testify/require"
)

func ToPtr[T any](v T) *T {
	return &v
}

func TestRateHost(t *testing.T) {
	rc := providers.RatingConfig{}
	// prc := providers.ProviderRatingConfig{}
	rc.Global.HighThreatCountryCodes = []string{"CN"}
	rc.Global.MediumThreatCountryCodes = []string{"US"}
	rc.ProviderRatingsConfigs.IPQS.ProxyScore = ToPtr(float64(3))
	rc.ProviderRatingsConfigs.IPQS.HighThreatCountryMatchScore = ToPtr(float64(4))
	rc.ProviderRatingsConfigs.IPQS.MediumThreatCountryMatchScore = ToPtr(float64(3))
	rc.ProviderRatingsConfigs.IPQS.BotScore = ToPtr(float64(6))
	rc.ProviderRatingsConfigs.IPQS.VPNScore = ToPtr(float64(5))
	ir := ipqsResp{
		Success:     false,
		Proxy:       false,
		CountryCode: "US",
		IsCrawler:   false,
		Vpn:         true,
		Tor:         false,
		ActiveVpn:   false,
		ActiveTor:   false,
		RecentAbuse: false,
		BotStatus:   false,
		FraudScore:  0,
	}

	res := rateHost(ir, rc)
	// success is false so should return 0
	require.Equal(t, float64(0), res.Score)
	// enable success
	ir.Success = true
	res = rateHost(ir, rc)
	// expect vpn to bring score up to 5
	require.Equal(t, float64(5), res.Score)
	// enabling bot should bring score up to 6
	ir.BotStatus = true
	res = rateHost(ir, rc)
	require.Equal(t, float64(6), res.Score)
}
