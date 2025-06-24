package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchLinode(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}

	result := fetchLinode("69.164.198.1", sess)
	require.NotNil(t, result.table)
}
