package ui

import (
	"log/slog"
	"testing"

	h "github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchICloudPR(t *testing.T) {
	sess = session.New()
	sess.Logger = slog.Default()
	sess.HTTPClient = h.GetHTTPClient()
	sess.UseTestData = true
	sess.Providers.ICloudPR.Enabled = ToPtr(true)
	result := fetchICloudPR("172.224.224.60", sess)
	require.NotNil(t, result.table)
}
