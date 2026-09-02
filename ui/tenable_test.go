package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/tenable"
	"github.com/stretchr/testify/require"
)

const (
	testIPTenable     = "192.0.2.1"
	testPrefixTenable = "192.0.2.1/32"
	testHeaderTenable = " Tenable | Host: "
)

func TestCreateTenableTable(t *testing.T) {
	result := &tenable.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixTenable),
	}

	table := createTenableTable(testIPTenable, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderTenable+testIPTenable, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixTenable, table.GetCell(1, 1).Text)
}

func TestCreateTenableTableActive(t *testing.T) {
	result := &tenable.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixTenable),
	}

	table := createTenableTable(testIPTenable, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Tenable | Host: "+testIPTenable, table.GetCell(0, 0).Text)
}

func TestCreateTenableTableNoMatch(t *testing.T) {
	table := createTenableTable(testIPTenable, &tenable.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderTenable+testIPTenable, table.GetCell(0, 0).Text)
	require.Equal(t, " No Tenable prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestTenableActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createTenableTable(testIPTenable, &tenable.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixTenable),
	}, false)

	addActiveIndicatorToTable(table, providerTenable)

	require.Equal(t, " ▶ Tenable | Host: "+testIPTenable, table.GetCell(0, 0).Text)
}
