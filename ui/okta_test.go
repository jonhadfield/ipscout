package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/okta"
	"github.com/stretchr/testify/require"
)

const (
	testIPOkta     = "192.0.2.1"
	testPrefixOkta = "192.0.2.1/32"
	testHeaderOkta = " Okta | Host: "
)

func TestCreateOktaTable(t *testing.T) {
	result := &okta.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixOkta),
	}

	table := createOktaTable(testIPOkta, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderOkta+testIPOkta, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixOkta, table.GetCell(1, 1).Text)
}

func TestCreateOktaTableActive(t *testing.T) {
	result := &okta.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixOkta),
	}

	table := createOktaTable(testIPOkta, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Okta | Host: "+testIPOkta, table.GetCell(0, 0).Text)
}

func TestCreateOktaTableNoMatch(t *testing.T) {
	table := createOktaTable(testIPOkta, &okta.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderOkta+testIPOkta, table.GetCell(0, 0).Text)
	require.Equal(t, " No Okta prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestOktaActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createOktaTable(testIPOkta, &okta.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixOkta),
	}, false)

	addActiveIndicatorToTable(table, providerOkta)

	require.Equal(t, " ▶ Okta | Host: "+testIPOkta, table.GetCell(0, 0).Text)
}
