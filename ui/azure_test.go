package ui

import (
	"log/slog"
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchAzure(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}
	// Initialize logger to prevent nil pointer dereference
	sess.Logger = slog.Default()

	result := fetchAzure("40.126.12.192", sess)
	require.NotNil(t, result.table)
}
