package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/airvpn"
	"github.com/stretchr/testify/require"
)

const (
	testIPAirVPN     = "192.0.2.1"
	testPrefixAirVPN = "192.0.2.0/24"
)

func TestCreateAirVPNTable(t *testing.T) {
	result := &airvpn.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixAirVPN),
	}

	table := createAirVPNTable(testIPAirVPN, result, false)
	require.NotNil(t, table)

	require.Equal(t, " AirVPN | Host: "+testIPAirVPN, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixAirVPN, table.GetCell(1, 1).Text)
}

func TestCreateAirVPNTableActiveState(t *testing.T) {
	result := &airvpn.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixAirVPN),
	}

	table := createAirVPNTable(testIPAirVPN, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ AirVPN | Host: "+testIPAirVPN, table.GetCell(0, 0).Text)
}

func TestCreateAirVPNTableNoMatch(t *testing.T) {
	table := createAirVPNTable(testIPExample, &airvpn.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " AirVPN | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in AirVPN ranges", table.GetCell(1, 0).Text)
}
