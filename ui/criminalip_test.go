package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchCriminalIP(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}

	result := fetchCriminalIP("1.1.1.1", sess)
	require.NotNil(t, result.table)
}
