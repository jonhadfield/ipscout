package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/nodeping"
	"github.com/stretchr/testify/require"
)

const (
	testIPNodePing     = "192.0.2.1"
	testPrefixNodePing = "192.0.2.0/24"
)

func TestCreateNodePingTable(t *testing.T) {
	result := &nodeping.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixNodePing),
	}

	table := createNodePingTable(testIPNodePing, result, false)
	require.NotNil(t, table)

	require.Equal(t, " NodePing | Host: "+testIPNodePing, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixNodePing, table.GetCell(1, 1).Text)
}

func TestCreateNodePingTableActiveState(t *testing.T) {
	result := &nodeping.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixNodePing),
	}

	table := createNodePingTable(testIPNodePing, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ NodePing | Host: "+testIPNodePing, table.GetCell(0, 0).Text)
}

func TestCreateNodePingTableNoMatch(t *testing.T) {
	table := createNodePingTable(testIPExample, &nodeping.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " NodePing | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in NodePing ranges", table.GetCell(1, 0).Text)
}
