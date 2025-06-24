package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchOVH(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}

	result := fetchOVH("137.74.112.1", sess)
	require.NotNil(t, result.table)
}
