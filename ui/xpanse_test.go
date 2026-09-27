package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/xpanse"
	"github.com/stretchr/testify/require"
)

const (
	testIPXpanse     = "192.0.2.1"
	testPrefixXpanse = "192.0.2.0/24"
)

func TestCreateXpanseTable(t *testing.T) {
	result := &xpanse.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixXpanse),
	}

	table := createXpanseTable(testIPXpanse, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Cortex Xpanse | Host: "+testIPXpanse, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixXpanse, table.GetCell(1, 1).Text)
}

func TestCreateXpanseTableActiveState(t *testing.T) {
	result := &xpanse.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixXpanse),
	}

	table := createXpanseTable(testIPXpanse, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Cortex Xpanse | Host: "+testIPXpanse, table.GetCell(0, 0).Text)
}

func TestCreateXpanseTableNoMatch(t *testing.T) {
	table := createXpanseTable(testIPExample, &xpanse.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Cortex Xpanse | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Cortex Xpanse ranges", table.GetCell(1, 0).Text)
}
