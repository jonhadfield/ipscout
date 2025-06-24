package ui

import (
	"log/slog"
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchGCP(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}
	// Initialize logger to prevent nil pointer dereference
	sess.Logger = slog.Default()

	result := fetchGCP("34.128.62.0", sess)
	require.NotNil(t, result.table)
}
