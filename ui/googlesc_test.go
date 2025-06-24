package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchGoogleSC(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}

	result := fetchGoogleSC("74.125.219.32", sess)
	require.NotNil(t, result.table)
}
