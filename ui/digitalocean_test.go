package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchDigitalOcean(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}

	result := fetchDigitalOcean("165.232.46.239", sess)
	require.NotNil(t, result.table)
}
