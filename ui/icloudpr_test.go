package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestFetchICloudPR(t *testing.T) {
	sess := &session.Session{
		UseTestData: true,
	}

	result := fetchICloudPR("172.224.224.60", sess)
	require.NotNil(t, result.table)
}
