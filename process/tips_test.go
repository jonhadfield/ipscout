package process

import (
	"path/filepath"
	"testing"

	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers/abuseipdb"
	"github.com/jonhadfield/ipscout/providers/ipqs"
	"github.com/jonhadfield/ipscout/registry"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func tipSession(t *testing.T) *session.Session {
	t.Helper()

	db, err := cache.Create(discardLogger(), filepath.Join(t.TempDir(), ".config", "ipscout"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	sess := session.New()
	sess.Logger = discardLogger()
	sess.Cache = db

	return sess
}

func TestAddSignupTipShownOncePerInterval(t *testing.T) {
	t.Parallel()

	sess := tipSession(t)

	addSignupTip(sess, sparseResultsThreshold)
	require.Len(t, sess.Messages.Info, 1)
	require.Contains(t, sess.Messages.Info[0], "IPQualityScore (IPQS_API_KEY, https://www.ipqualityscore.com/create-account)")
	require.Contains(t, sess.Messages.Info[0], "AbuseIPDB (ABUSEIPDB_API_KEY")
	require.Contains(t, sess.Messages.Info[0], "global.disable_tips")

	// the cache records the tip, so a second sparse lookup stays quiet
	addSignupTip(sess, 0)
	require.Len(t, sess.Messages.Info, 1)
}

func TestAddSignupTipSuppressed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		results int
		setup   func(*session.Session)
	}{
		{"enough results", sparseResultsThreshold + 1, func(*session.Session) {}},
		{"json output", 0, func(s *session.Session) { s.Config.Global.Output = outputJSON }},
		{"tips disabled", 0, func(s *session.Session) { s.Config.Global.DisableTips = true }},
		{"provider filter", 0, func(s *session.Session) { s.Config.Global.FilterProviders = []string{"aws"} }},
		{"test data", 0, func(s *session.Session) { s.UseTestData = true }},
		{"no cache", 0, func(s *session.Session) { s.Cache = nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sess := tipSession(t)
			tt.setup(sess)

			addSignupTip(sess, tt.results)
			require.Empty(t, sess.Messages.Info)
		})
	}
}

func TestSignupTipsOrder(t *testing.T) {
	t.Parallel()

	// with IPQS set up, the next ranked providers are suggested
	sess := session.New()
	enabled := true
	sess.Providers.IPQS.Enabled = &enabled
	sess.Providers.IPQS.APIKey = "key"

	tips := signupTips(registry.Unconfigured(*sess))
	require.Len(t, tips, signupTipsShown)
	require.Contains(t, tips[0], "AbuseIPDB")
	require.Contains(t, tips[1], "IPAPI")

	for _, tip := range tips {
		require.NotContains(t, tip, "IPQualityScore")
	}

	require.Less(t, tipRank(ipqs.ProviderName), tipRank(abuseipdb.ProviderName))
	require.Equal(t, len(signupTipOrder), tipRank("unranked"))
}
