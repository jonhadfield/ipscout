package ui

import (
	"log/slog"
	"testing"

	h "github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchBingbot(t *testing.T) {
	sess = session.New()
	sess.Logger = slog.Default()
	sess.HTTPClient = h.GetHTTPClient()
	sess.UseTestData = true
	sess.Providers.Bingbot.Enabled = ToPtr(true)

	result := fetchBingbot("157.55.39.0", sess)
	require.NotNil(t, result.table)
}
