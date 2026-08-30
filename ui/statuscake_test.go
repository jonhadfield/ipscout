package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/statuscake"
	"github.com/stretchr/testify/require"
)

const (
	testIPStatusCake     = "192.0.2.1"
	testPrefixStatusCake = "192.0.2.1/32"
	testHeaderStatusCake = " StatusCake | Host: "
)

func TestCreateStatusCakeTable(t *testing.T) {
	result := &statuscake.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixStatusCake),
	}

	table := createStatusCakeTable(testIPStatusCake, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderStatusCake+testIPStatusCake, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixStatusCake, table.GetCell(1, 1).Text)
}

func TestCreateStatusCakeTableActive(t *testing.T) {
	result := &statuscake.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixStatusCake),
	}

	table := createStatusCakeTable(testIPStatusCake, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ StatusCake | Host: "+testIPStatusCake, table.GetCell(0, 0).Text)
}

func TestCreateStatusCakeTableNoMatch(t *testing.T) {
	table := createStatusCakeTable(testIPStatusCake, &statuscake.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderStatusCake+testIPStatusCake, table.GetCell(0, 0).Text)
	require.Equal(t, " No StatusCake prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestStatusCakeActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createStatusCakeTable(testIPStatusCake, &statuscake.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixStatusCake),
	}, false)

	addActiveIndicatorToTable(table, providerStatusCake)

	require.Equal(t, " ▶ StatusCake | Host: "+testIPStatusCake, table.GetCell(0, 0).Text)
}
