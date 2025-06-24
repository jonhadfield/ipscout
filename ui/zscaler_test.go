package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchZscaler(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}

	result := fetchZscaler("165.225.16.1", sess)
	require.NotNil(t, result.table)
}
