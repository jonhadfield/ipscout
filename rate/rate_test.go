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
