package rate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jonhadfield/ipscout/providers"
	"github.com/stretchr/testify/require"
)

func TestLoadDefaultConfig(t *testing.T) {
	var ratingConfig providers.RatingConfig

	ratingConfigJSON, err := os.ReadFile(filepath.Join("testdata", "ratingConfig.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(ratingConfigJSON, &ratingConfig))
	require.Equal(t, float64(7), ratingConfig.ProviderRatingsConfigs.AWS.DefaultMatchScore)
	require.Equal(t, float64(7), ratingConfig.ProviderRatingsConfigs.Azure.DefaultMatchScore)
	require.Equal(t, float64(7), ratingConfig.ProviderRatingsConfigs.GCP.DefaultMatchScore)
	require.Equal(t, float64(8), ratingConfig.ProviderRatingsConfigs.Google.DefaultMatchScore)
	require.Equal(t, float64(1), ratingConfig.ProviderRatingsConfigs.Googlebot.DefaultMatchScore)
	require.Equal(t, float64(8), ratingConfig.ProviderRatingsConfigs.Linode.DefaultMatchScore)
}

// TestDefaultConfigHostingProviderScores verifies that the hosting providers
// whose rating was newly activated are present in the embedded default config
// with a non-zero match score, so that `ipscout rate` actually scores matches
// instead of silently producing a zero score.
func TestDefaultConfigHostingProviderScores(t *testing.T) {
	var ratingConfig providers.RatingConfig

	require.NoError(t, json.Unmarshal([]byte(DefaultRatingConfigJSON), &ratingConfig))
	require.Equal(t, float64(8), ratingConfig.ProviderRatingsConfigs.Alibaba.DefaultMatchScore)
	require.Equal(t, float64(8), ratingConfig.ProviderRatingsConfigs.M247.DefaultMatchScore)
	require.Equal(t, float64(8), ratingConfig.ProviderRatingsConfigs.Scaleway.DefaultMatchScore)
	require.Equal(t, float64(8), ratingConfig.ProviderRatingsConfigs.Vultr.DefaultMatchScore)
	require.Equal(t, float64(1), ratingConfig.ProviderRatingsConfigs.GoogleSC.DefaultMatchScore)
}

// TestDefaultConfigNewIPFetcherProviderScores verifies the providers added from
// the ip-fetcher integration are present in the embedded default config with
// their expected match scores (IaaS 8.0, CDN/WAF 5.0, SaaS 3.0).
func TestDefaultConfigNewIPFetcherProviderScores(t *testing.T) {
	var ratingConfig providers.RatingConfig

	require.NoError(t, json.Unmarshal([]byte(DefaultRatingConfigJSON), &ratingConfig))

	rc := ratingConfig.ProviderRatingsConfigs
	require.Equal(t, float64(8), rc.Contabo.DefaultMatchScore)
	require.Equal(t, float64(8), rc.Flyio.DefaultMatchScore)
	require.Equal(t, float64(8), rc.IBMCloud.DefaultMatchScore)
	require.Equal(t, float64(8), rc.Leaseweb.DefaultMatchScore)
	require.Equal(t, float64(8), rc.Render.DefaultMatchScore)
	require.Equal(t, float64(8), rc.Tencent.DefaultMatchScore)
	require.Equal(t, float64(5), rc.Bunny.DefaultMatchScore)
	require.Equal(t, float64(5), rc.CDN77.DefaultMatchScore)
	require.Equal(t, float64(5), rc.Imperva.DefaultMatchScore)
	require.Equal(t, float64(3), rc.Atlassian.DefaultMatchScore)
	require.Equal(t, float64(3), rc.Datadog.DefaultMatchScore)
	require.Equal(t, float64(3), rc.Stripe.DefaultMatchScore)
}
