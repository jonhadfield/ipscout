package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/surfshark"
	"github.com/stretchr/testify/require"
)

const (
	testIPSurfshark     = "192.0.2.1"
	testPrefixSurfshark = "192.0.2.0/24"
)

func TestCreateSurfsharkTable(t *testing.T) {
	result := &surfshark.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixSurfshark),
	}

	table := createSurfsharkTable(testIPSurfshark, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Surfshark | Host: "+testIPSurfshark, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixSurfshark, table.GetCell(1, 1).Text)
}

func TestCreateSurfsharkTableActiveState(t *testing.T) {
	result := &surfshark.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixSurfshark),
	}

	table := createSurfsharkTable(testIPSurfshark, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Surfshark | Host: "+testIPSurfshark, table.GetCell(0, 0).Text)
}

func TestCreateSurfsharkTableNoMatch(t *testing.T) {
	table := createSurfsharkTable(testIPExample, &surfshark.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Surfshark | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Surfshark ranges", table.GetCell(1, 0).Text)
}
