package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/applebot"
	"github.com/stretchr/testify/require"
)

const (
	testIPApplebot     = "17.241.208.165"
	testPrefixApplebot = "17.241.208.160/27"
	testHeaderApplebot = " Applebot | Host: "
)

func TestCreateApplebotTable(t *testing.T) {
	creationTime := time.Date(2023, 10, 27, 10, 0, 0, 0, time.UTC)

	result := &applebot.HostSearchResult{
		Prefix:       netip.MustParsePrefix(testPrefixApplebot),
		CreationTime: creationTime,
	}

	table := createApplebotTable(testIPApplebot, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderApplebot+testIPApplebot, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixApplebot, table.GetCell(1, 1).Text)
	require.Equal(t, " Creation Time", table.GetCell(2, 0).Text)
	require.Equal(t, creationTime.String(), table.GetCell(2, 1).Text)
}

func TestCreateApplebotTableNoMatch(t *testing.T) {
	table := createApplebotTable(testIPApplebot, &applebot.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderApplebot+testIPApplebot, table.GetCell(0, 0).Text)
	require.Equal(t, " No Applebot prefix found", table.GetCell(1, 0).Text)
}
