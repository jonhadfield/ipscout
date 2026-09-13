package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/m365"
	"github.com/stretchr/testify/require"
)

const (
	testIPM365     = "192.0.2.1"
	testPrefixM365 = "192.0.2.1/32"
	testHeaderM365 = " Microsoft 365 | Host: "
)

func TestCreateM365Table(t *testing.T) {
	result := &m365.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixM365),
	}

	table := createM365Table(testIPM365, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderM365+testIPM365, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixM365, table.GetCell(1, 1).Text)
}

func TestCreateM365TableActive(t *testing.T) {
	result := &m365.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixM365),
	}

	table := createM365Table(testIPM365, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Microsoft 365 | Host: "+testIPM365, table.GetCell(0, 0).Text)
}

func TestCreateM365TableNoMatch(t *testing.T) {
	table := createM365Table(testIPM365, &m365.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderM365+testIPM365, table.GetCell(0, 0).Text)
	require.Equal(t, " No Microsoft 365 prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestM365ActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createM365Table(testIPM365, &m365.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixM365),
	}, false)

	addActiveIndicatorToTable(table, providerM365)

	require.Equal(t, " ▶ Microsoft 365 | Host: "+testIPM365, table.GetCell(0, 0).Text)
}
