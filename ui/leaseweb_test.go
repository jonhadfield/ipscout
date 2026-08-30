package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/leaseweb"
	"github.com/stretchr/testify/require"
)

const (
	testIPLeaseweb     = "5.79.64.1"
	testPrefixLeaseweb = "5.79.64.0/18"
)

func TestCreateLeasewebTable(t *testing.T) {
	result := &leaseweb.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixLeaseweb),
	}

	table := createLeasewebTable(testIPLeaseweb, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Leaseweb | Host: "+testIPLeaseweb, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixLeaseweb, table.GetCell(1, 1).Text)
}

func TestCreateLeasewebTableActiveState(t *testing.T) {
	result := &leaseweb.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixLeaseweb),
	}

	table := createLeasewebTable(testIPLeaseweb, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Leaseweb | Host: "+testIPLeaseweb, table.GetCell(0, 0).Text)
}

func TestCreateLeasewebTableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in Leaseweb ranges.
	table := createLeasewebTable(testIPExample, &leaseweb.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Leaseweb | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Leaseweb ranges", table.GetCell(1, 0).Text)
}
