package ui

import (
	"log/slog"
	"testing"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchZscaler(t *testing.T) {
	sess = session.New()
	sess.UseTestData = true
	sess.HTTPClient = helpers.GetHTTPClient()
	sess.Logger = slog.Default()
	sess.Providers.Zscaler.Enabled = ToPtr(true)

	result := fetchZscaler("165.225.16.1", sess)
	require.NotNil(t, result.table)
}
