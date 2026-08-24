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
	require.Equal(t, float64(1), ratingConfig.ProviderRatingsConfigs.OpenAI.DefaultMatchScore)
}

// TestDefaultConfigNewIPFetcherProviderScores verifies the providers added from
// the ip-fetcher integration are present in the embedded default config with
// their expected match scores (IaaS 8.0, CDN/WAF 5.0, SaaS 3.0, edge/CDN and
// SaaS ranges 2.0, crawlers 1.0).
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
	require.Equal(t, float64(2), rc.Akamai.DefaultMatchScore)
	require.Equal(t, float64(2), rc.Cloudflare.DefaultMatchScore)
	require.Equal(t, float64(2), rc.Fastly.DefaultMatchScore)
	require.Equal(t, float64(2), rc.GitHub.DefaultMatchScore)
	require.Equal(t, float64(1), rc.GoogleUTF.DefaultMatchScore)
	require.Equal(t, float64(8), rc.OCI.DefaultMatchScore)
	require.Equal(t, float64(1), rc.Ahrefs.DefaultMatchScore)
	require.Equal(t, float64(1), rc.Applebot.DefaultMatchScore)
	require.Equal(t, float64(1), rc.DuckDuckBot.DefaultMatchScore)
	require.Equal(t, float64(1), rc.PerplexityBot.DefaultMatchScore)
}

// The shipped config always sets a rating config path but never writes the
// file, so an absent file falls back to the built-in defaults rather than
// leaving rating unusable.
func TestGetRatingConfigFallsBackWhenFileAbsent(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "ratingConfig.json")

	got, err := GetRatingConfig(missing)
	require.NoError(t, err)
	require.JSONEq(t, DefaultRatingConfigJSON, string(got))
}

// A file that exists but cannot be parsed is still an error; only absence is
// tolerated.
func TestGetRatingConfigErrorsOnInvalidFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ratingConfig.json")
	require.NoError(t, os.WriteFile(path, []byte("{ not json"), 0o600))

	_, err := GetRatingConfig(path)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "does not exist")
}

// An explicit, valid config is read from disk rather than replaced by defaults.
func TestGetRatingConfigReadsExistingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ratingConfig.json")
	custom := `{"global":{"blockScoreThreshold":9.5,"highThreatCountryCodes":[],"mediumThreatCountryCodes":[]},"providers":{}}`
	require.NoError(t, os.WriteFile(path, []byte(custom), 0o600))

	got, err := GetRatingConfig(path)
	require.NoError(t, err)
	require.JSONEq(t, custom, string(got))
}
