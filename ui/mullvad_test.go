package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/mullvad"
	"github.com/stretchr/testify/require"
)

const (
	testIPMullvad     = "192.0.2.1"
	testPrefixMullvad = "192.0.2.0/24"
)

func TestCreateMullvadTable(t *testing.T) {
	result := &mullvad.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixMullvad),
	}

	table := createMullvadTable(testIPMullvad, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Mullvad | Host: "+testIPMullvad, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixMullvad, table.GetCell(1, 1).Text)
}

func TestCreateMullvadTableActiveState(t *testing.T) {
	result := &mullvad.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixMullvad),
	}

	table := createMullvadTable(testIPMullvad, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Mullvad | Host: "+testIPMullvad, table.GetCell(0, 0).Text)
}

func TestCreateMullvadTableNoMatch(t *testing.T) {
	table := createMullvadTable(testIPExample, &mullvad.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Mullvad | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Mullvad ranges", table.GetCell(1, 0).Text)
}
