package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/invicti"
	"github.com/stretchr/testify/require"
)

const (
	testIPInvicti     = "192.0.2.1"
	testPrefixInvicti = "192.0.2.0/24"
)

func TestCreateInvictiTable(t *testing.T) {
	result := &invicti.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixInvicti),
	}

	table := createInvictiTable(testIPInvicti, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Invicti | Host: "+testIPInvicti, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixInvicti, table.GetCell(1, 1).Text)
}

func TestCreateInvictiTableActiveState(t *testing.T) {
	result := &invicti.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixInvicti),
	}

	table := createInvictiTable(testIPInvicti, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Invicti | Host: "+testIPInvicti, table.GetCell(0, 0).Text)
}

func TestCreateInvictiTableNoMatch(t *testing.T) {
	table := createInvictiTable(testIPExample, &invicti.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Invicti | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Invicti ranges", table.GetCell(1, 0).Text)
}
