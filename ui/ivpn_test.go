package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/ivpn"
	"github.com/stretchr/testify/require"
)

const (
	testIPIVPN     = "192.0.2.1"
	testPrefixIVPN = "192.0.2.0/24"
)

func TestCreateIVPNTable(t *testing.T) {
	result := &ivpn.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixIVPN),
	}

	table := createIVPNTable(testIPIVPN, result, false)
	require.NotNil(t, table)

	require.Equal(t, " IVPN | Host: "+testIPIVPN, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixIVPN, table.GetCell(1, 1).Text)
}

func TestCreateIVPNTableActiveState(t *testing.T) {
	result := &ivpn.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixIVPN),
	}

	table := createIVPNTable(testIPIVPN, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ IVPN | Host: "+testIPIVPN, table.GetCell(0, 0).Text)
}

func TestCreateIVPNTableNoMatch(t *testing.T) {
	table := createIVPNTable(testIPExample, &ivpn.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " IVPN | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in IVPN ranges", table.GetCell(1, 0).Text)
}
