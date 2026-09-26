package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/hetrixtools"
	"github.com/stretchr/testify/require"
)

const (
	testIPHetrixTools     = "192.0.2.1"
	testPrefixHetrixTools = "192.0.2.0/24"
)

func TestCreateHetrixToolsTable(t *testing.T) {
	result := &hetrixtools.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixHetrixTools),
	}

	table := createHetrixToolsTable(testIPHetrixTools, result, false)
	require.NotNil(t, table)

	require.Equal(t, " HetrixTools | Host: "+testIPHetrixTools, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixHetrixTools, table.GetCell(1, 1).Text)
}

func TestCreateHetrixToolsTableActiveState(t *testing.T) {
	result := &hetrixtools.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixHetrixTools),
	}

	table := createHetrixToolsTable(testIPHetrixTools, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ HetrixTools | Host: "+testIPHetrixTools, table.GetCell(0, 0).Text)
}

func TestCreateHetrixToolsTableNoMatch(t *testing.T) {
	table := createHetrixToolsTable(testIPExample, &hetrixtools.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " HetrixTools | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in HetrixTools ranges", table.GetCell(1, 0).Text)
}
