package ui

import (
	"log/slog"
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchPTR(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}
	// Initialize logger to prevent nil pointer dereference
	sess.Logger = slog.Default()

	result := fetchPTR("8.8.8.8", sess)
	require.NotNil(t, result.table)
}
