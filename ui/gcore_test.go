package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/gcore"
	"github.com/stretchr/testify/require"
)

const (
	testIPGcore     = "192.0.2.1"
	testPrefixGcore = "192.0.2.1/32"
	testHeaderGcore = " Gcore | Host: "
)

func TestCreateGcoreTable(t *testing.T) {
	result := &gcore.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixGcore),
	}

	table := createGcoreTable(testIPGcore, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderGcore+testIPGcore, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixGcore, table.GetCell(1, 1).Text)
}

func TestCreateGcoreTableActive(t *testing.T) {
	result := &gcore.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixGcore),
	}

	table := createGcoreTable(testIPGcore, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Gcore | Host: "+testIPGcore, table.GetCell(0, 0).Text)
}

func TestCreateGcoreTableNoMatch(t *testing.T) {
	table := createGcoreTable(testIPGcore, &gcore.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderGcore+testIPGcore, table.GetCell(0, 0).Text)
	require.Equal(t, " No Gcore prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestGcoreActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createGcoreTable(testIPGcore, &gcore.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixGcore),
	}, false)

	addActiveIndicatorToTable(table, providerGcore)

	require.Equal(t, " ▶ Gcore | Host: "+testIPGcore, table.GetCell(0, 0).Text)
}
