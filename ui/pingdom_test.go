package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/pingdom"
	"github.com/stretchr/testify/require"
)

const (
	testIPPingdom     = "192.0.2.1"
	testPrefixPingdom = "192.0.2.1/32"
	testHeaderPingdom = " Pingdom | Host: "
)

func TestCreatePingdomTable(t *testing.T) {
	result := &pingdom.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixPingdom),
	}

	table := createPingdomTable(testIPPingdom, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderPingdom+testIPPingdom, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixPingdom, table.GetCell(1, 1).Text)
}

func TestCreatePingdomTableActive(t *testing.T) {
	result := &pingdom.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixPingdom),
	}

	table := createPingdomTable(testIPPingdom, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Pingdom | Host: "+testIPPingdom, table.GetCell(0, 0).Text)
}

func TestCreatePingdomTableNoMatch(t *testing.T) {
	table := createPingdomTable(testIPPingdom, &pingdom.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderPingdom+testIPPingdom, table.GetCell(0, 0).Text)
	require.Equal(t, " No Pingdom prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestPingdomActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createPingdomTable(testIPPingdom, &pingdom.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixPingdom),
	}, false)

	addActiveIndicatorToTable(table, providerPingdom)

	require.Equal(t, " ▶ Pingdom | Host: "+testIPPingdom, table.GetCell(0, 0).Text)
}
