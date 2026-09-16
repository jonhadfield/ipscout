package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/ccbot"
	"github.com/stretchr/testify/require"
)

const (
	testIPCCBot     = "192.0.2.1"
	testPrefixCCBot = "192.0.2.0/24"
	testHeaderCCBot = " CCBot | Host: "
)

func TestCreateCCBotTable(t *testing.T) {
	creationTime := time.Date(2023, 10, 27, 10, 0, 0, 0, time.UTC)

	result := &ccbot.HostSearchResult{
		Prefix:       netip.MustParsePrefix(testPrefixCCBot),
		CreationTime: creationTime,
	}

	table := createCCBotTable(testIPCCBot, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderCCBot+testIPCCBot, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixCCBot, table.GetCell(1, 1).Text)
	require.Equal(t, " Creation Time", table.GetCell(2, 0).Text)
	require.Equal(t, creationTime.String(), table.GetCell(2, 1).Text)
}

func TestCreateCCBotTableNoMatch(t *testing.T) {
	table := createCCBotTable(testIPCCBot, &ccbot.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderCCBot+testIPCCBot, table.GetCell(0, 0).Text)
	require.Equal(t, " No CCBot prefix found", table.GetCell(1, 0).Text)
}
