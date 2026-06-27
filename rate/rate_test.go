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
