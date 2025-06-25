package ui

import (
	"log/slog"
	"testing"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchOVH(t *testing.T) {
	sess = session.New()
	sess.Logger = slog.Default()
	sess.HTTPClient = helpers.GetHTTPClient()
	sess.Providers.OVH.Enabled = ToPtr(true)

	result := fetchOVH("137.74.112.1", sess)
	require.NotNil(t, result.table)
}
