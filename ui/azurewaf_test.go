package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchAzureWAF(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}

	result := fetchAzureWAF("165.232.46.239", sess)
	require.NotNil(t, result.table)
}
