package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/intruder"
	"github.com/stretchr/testify/require"
)

const (
	testIPIntruder     = "192.0.2.1"
	testPrefixIntruder = "192.0.2.0/24"
)

func TestCreateIntruderTable(t *testing.T) {
	result := &intruder.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixIntruder),
	}

	table := createIntruderTable(testIPIntruder, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Intruder | Host: "+testIPIntruder, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixIntruder, table.GetCell(1, 1).Text)
}

func TestCreateIntruderTableActiveState(t *testing.T) {
	result := &intruder.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixIntruder),
	}

	table := createIntruderTable(testIPIntruder, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Intruder | Host: "+testIPIntruder, table.GetCell(0, 0).Text)
}

func TestCreateIntruderTableNoMatch(t *testing.T) {
	table := createIntruderTable(testIPExample, &intruder.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Intruder | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Intruder ranges", table.GetCell(1, 0).Text)
}
