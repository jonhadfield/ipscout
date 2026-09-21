package runner

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers/abuseipdb"
	"github.com/jonhadfield/ipscout/providers/criminalip"
	"github.com/jonhadfield/ipscout/providers/ipapi"
	"github.com/jonhadfield/ipscout/providers/ipqs"
	"github.com/jonhadfield/ipscout/providers/shodan"
	"github.com/jonhadfield/ipscout/providers/virustotal"
	"github.com/jonhadfield/ipscout/registry"
	"github.com/jonhadfield/ipscout/session"
)

const (
	// sparseResultsThreshold is the most providers that can return data for
	// a lookup to still count as sparse enough to suggest API keys
	sparseResultsThreshold = 4
	// signupTipsShown is how many keyed providers a tip suggests
	signupTipsShown = 2
	// signupTipInterval is the least time between two tips
	signupTipInterval = 24 * time.Hour
	signupTipCacheKey = "tip_signup_shown"
)

// signupTipOrder ranks keyed providers for suggestion, those with a free tier
// first: ipapi.co directs keyless users to a paid plan.
var signupTipOrder = []string{
	ipqs.ProviderName,
	abuseipdb.ProviderName,
	ipapi.ProviderName,
	virustotal.ProviderName,
	shodan.ProviderName,
	criminalip.ProviderName,
}

// SignupTip returns a tip suggesting API keys for keyed providers that are not
// set up, when few providers returned data for the host, or "" when no tip is
// due. A tip is due at most once per signupTipInterval, never for JSON output,
// filtered lookups or test data, nor when tips are disabled, and needs the
// cache to record when one was last given.
func SignupTip(sess *session.Session, matchingResults int) string {
	if matchingResults > sparseResultsThreshold || sess.UseTestData || sess.Cache == nil ||
		sess.Config.Global.DisableTips || len(sess.Config.Global.FilterProviders) > 0 ||
		strings.EqualFold(sess.Config.Global.Output, "json") {
		return ""
	}

	tips := signupTips(registry.Unconfigured(*sess))
	if len(tips) == 0 {
		return ""
	}

	if item, err := cache.Read(sess.Logger, sess.Cache, signupTipCacheKey); err == nil && item != nil {
		return ""
	}

	if err := cache.UpsertWithTTL(sess.Logger, sess.Cache, cache.Item{
		AppVersion: sess.App.SemVer,
		Key:        signupTipCacheKey,
		Value:      []byte("1"),
		Created:    time.Now(),
	}, signupTipInterval); err != nil {
		sess.Logger.Debug("failed to record signup tip", "error", err)

		return ""
	}

	return fmt.Sprintf("few providers had data on this host. API keys unlock more, and most providers offer a free tier: %s. "+
		"Set the key and enable the provider in your config, or set global.disable_tips to true to hide this tip.", strings.Join(tips, "; "))
}

// signupTips describes the first signupTipsShown of the unconfigured keyed
// providers in signupTipOrder.
func signupTips(unconfigured []registry.Entry) []string {
	slices.SortStableFunc(unconfigured, func(a, b registry.Entry) int {
		return tipRank(a.Name) - tipRank(b.Name)
	})

	var tips []string

	for _, e := range unconfigured {
		if len(tips) == signupTipsShown {
			break
		}

		tips = append(tips, fmt.Sprintf("%s (%s, %s)", e.DisplayName, e.KeyEnv, e.SignupURL))
	}

	return tips
}

func tipRank(name string) int {
	if i := slices.Index(signupTipOrder, name); i != -1 {
		return i
	}

	return len(signupTipOrder)
}
