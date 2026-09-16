package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/intercom"
	"github.com/stretchr/testify/require"
)

const (
	testIPIntercom     = "192.0.2.1"
	testPrefixIntercom = "192.0.2.0/24"
)

func TestCreateIntercomTable(t *testing.T) {
	result := &intercom.HostSearchResult{
		Prefix:  netip.MustParsePrefix(testPrefixIntercom),
		Region:  "US",
		Service: "web",
	}

	table := createIntercomTable(testIPIntercom, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Intercom | Host: "+testIPIntercom, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixIntercom, table.GetCell(1, 1).Text)
	require.Equal(t, " Region", table.GetCell(2, 0).Text)
	require.Equal(t, "US", table.GetCell(2, 1).Text)
	require.Equal(t, " Service", table.GetCell(3, 0).Text)
	require.Equal(t, "web", table.GetCell(3, 1).Text)
}

func TestCreateIntercomTableActiveState(t *testing.T) {
	result := &intercom.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixIntercom),
	}

	table := createIntercomTable(testIPIntercom, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Intercom | Host: "+testIPIntercom, table.GetCell(0, 0).Text)
}

func TestCreateIntercomTableNoMatch(t *testing.T) {
	table := createIntercomTable(testIPExample, &intercom.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Intercom | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Intercom ranges", table.GetCell(1, 0).Text)
}
