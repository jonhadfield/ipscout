package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/blocklistde"
	"github.com/stretchr/testify/require"
)

const (
	testIPBlocklistDE     = "192.0.2.1"
	testPrefixBlocklistDE = "192.0.2.1/32"
	testHeaderBlocklistDE = " Blocklist.de | Host: "
)

func TestCreateBlocklistDETable(t *testing.T) {
	result := &blocklistde.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixBlocklistDE),
	}

	table := createBlocklistDETable(testIPBlocklistDE, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderBlocklistDE+testIPBlocklistDE, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixBlocklistDE, table.GetCell(1, 1).Text)
}

func TestCreateBlocklistDETableActive(t *testing.T) {
	result := &blocklistde.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixBlocklistDE),
	}

	table := createBlocklistDETable(testIPBlocklistDE, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Blocklist.de | Host: "+testIPBlocklistDE, table.GetCell(0, 0).Text)
}

func TestCreateBlocklistDETableNoMatch(t *testing.T) {
	table := createBlocklistDETable(testIPBlocklistDE, &blocklistde.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderBlocklistDE+testIPBlocklistDE, table.GetCell(0, 0).Text)
	require.Equal(t, " No Blocklist.de prefix found", table.GetCell(1, 0).Text)
}
