package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchBingbot(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}

	result := fetchBingbot("157.55.39.0", sess)
	require.NotNil(t, result.table)
}
