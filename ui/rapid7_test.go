package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/rapid7"
	"github.com/stretchr/testify/require"
)

const (
	testIPRapid7     = "192.0.2.1"
	testPrefixRapid7 = "192.0.2.0/24"
)

func TestCreateRapid7Table(t *testing.T) {
	result := &rapid7.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixRapid7),
	}

	table := createRapid7Table(testIPRapid7, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Rapid7 | Host: "+testIPRapid7, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixRapid7, table.GetCell(1, 1).Text)
}

func TestCreateRapid7TableActiveState(t *testing.T) {
	result := &rapid7.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixRapid7),
	}

	table := createRapid7Table(testIPRapid7, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Rapid7 | Host: "+testIPRapid7, table.GetCell(0, 0).Text)
}

func TestCreateRapid7TableNoMatch(t *testing.T) {
	table := createRapid7Table(testIPExample, &rapid7.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Rapid7 | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Rapid7 ranges", table.GetCell(1, 0).Text)
}
