package ui

import (
	"log/slog"
	"testing"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchM247(t *testing.T) {
	sess = session.New()
	sess.Logger = slog.Default()
	sess.HTTPClient = helpers.GetHTTPClient()
	sess.UseTestData = true
	sess.Providers.M247.Enabled = ToPtr(true)

	result := fetchM247("89.249.76.0", sess)
	require.NotNil(t, result.table)
}
