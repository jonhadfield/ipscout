package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/flyio"
	"github.com/stretchr/testify/require"
)

const (
	testIPFlyio     = "66.241.124.1"
	testPrefixFlyio = "66.241.124.0/24"
)

func TestCreateFlyioTable(t *testing.T) {
	result := &flyio.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixFlyio),
	}

	table := createFlyioTable(testIPFlyio, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Fly.io | Host: "+testIPFlyio, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixFlyio, table.GetCell(1, 1).Text)
}

func TestCreateFlyioTableActiveState(t *testing.T) {
	result := &flyio.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixFlyio),
	}

	table := createFlyioTable(testIPFlyio, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Fly.io | Host: "+testIPFlyio, table.GetCell(0, 0).Text)
}

func TestCreateFlyioTableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in Fly.io ranges.
	table := createFlyioTable(testIPExample, &flyio.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Fly.io | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Fly.io ranges", table.GetCell(1, 0).Text)
}
