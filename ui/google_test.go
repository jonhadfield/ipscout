package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchGoogle(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}

	result := fetchGoogle("34.3.8.8", sess)
	require.NotNil(t, result.table)
}
