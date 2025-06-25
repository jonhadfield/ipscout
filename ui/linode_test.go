package ui

import (
	"log/slog"
	"testing"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchLinode(t *testing.T) {
	sess = session.New()
	sess.UseTestData = true
	sess.HTTPClient = helpers.GetHTTPClient()
	sess.Logger = slog.Default()
	sess.Providers.Linode.Enabled = ToPtr(true)

	result := fetchLinode("69.164.198.1", sess)
	require.NotNil(t, result.table)
}
