package cmd

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// The shipped config now uses use_ai and openai_api_key, matching the keys the
// reader looks up and the underscore convention used everywhere else.
func TestRatingConfigReadsUnderscoreKeys(t *testing.T) {
	v := viper.New()
	v.Set("rating.use_ai", true)
	v.Set("rating.openai_api_key", "sk-underscore")

	sess := session.New()
	require.NoError(t, initSessionConfig(sess, v))

	require.True(t, sess.Config.Rating.UseAI)
	require.Equal(t, "sk-underscore", sess.Config.Rating.OpenAIAPIKey)
}

// Config files written before the keys were corrected use hyphens. They were
// silently ignored, so they are still read to fix existing installs.
func TestRatingConfigReadsLegacyHyphenKeys(t *testing.T) {
	v := viper.New()
	v.Set("rating.use-ai", true)
	v.Set("rating.openai-api-key", "sk-hyphen")

	sess := session.New()
	require.NoError(t, initSessionConfig(sess, v))

	require.True(t, sess.Config.Rating.UseAI)
	require.Equal(t, "sk-hyphen", sess.Config.Rating.OpenAIAPIKey)
}

// The corrected key wins when both are present.
func TestRatingConfigPrefersUnderscoreKey(t *testing.T) {
	v := viper.New()
	v.Set("rating.openai_api_key", "sk-underscore")
	v.Set("rating.openai-api-key", "sk-hyphen")

	sess := session.New()
	require.NoError(t, initSessionConfig(sess, v))

	require.Equal(t, "sk-underscore", sess.Config.Rating.OpenAIAPIKey)
}

// The shipped default config must use the keys the reader looks up.
func TestShippedConfigUsesUnderscoreRatingKeys(t *testing.T) {
	require.Contains(t, session.DefaultConfig, "use_ai:")
	require.Contains(t, session.DefaultConfig, "openai_api_key:")
	require.NotContains(t, session.DefaultConfig, "use-ai:")
	require.NotContains(t, session.DefaultConfig, "openai-api-key:")
}
