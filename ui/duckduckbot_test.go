package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/duckduckbot"
	"github.com/stretchr/testify/require"
)

const (
	testIPDuckDuckBot     = "104.43.54.127"
	testPrefixDuckDuckBot = "104.43.54.127/32"
	testHeaderDuckDuckBot = " DuckDuckBot | Host: "
)

func TestCreateDuckDuckBotTable(t *testing.T) {
	creationTime := time.Date(2026, 7, 3, 15, 15, 37, 0, time.UTC)

	result := &duckduckbot.HostSearchResult{
		Prefix:       netip.MustParsePrefix(testPrefixDuckDuckBot),
		CreationTime: creationTime,
	}

	table := createDuckDuckBotTable(testIPDuckDuckBot, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderDuckDuckBot+testIPDuckDuckBot, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixDuckDuckBot, table.GetCell(1, 1).Text)
	require.Equal(t, " Creation Time", table.GetCell(2, 0).Text)
	require.Equal(t, creationTime.String(), table.GetCell(2, 1).Text)
}

func TestCreateDuckDuckBotTableNoMatch(t *testing.T) {
	table := createDuckDuckBotTable(testIPDuckDuckBot, &duckduckbot.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderDuckDuckBot+testIPDuckDuckBot, table.GetCell(0, 0).Text)
	require.Equal(t, " No DuckDuckBot prefix found", table.GetCell(1, 0).Text)
}
