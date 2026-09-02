package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/uptrends"
	"github.com/stretchr/testify/require"
)

const (
	testIPUptrends     = "192.0.2.1"
	testPrefixUptrends = "192.0.2.1/32"
	testHeaderUptrends = " Uptrends | Host: "
)

func TestCreateUptrendsTable(t *testing.T) {
	result := &uptrends.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixUptrends),
	}

	table := createUptrendsTable(testIPUptrends, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderUptrends+testIPUptrends, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixUptrends, table.GetCell(1, 1).Text)
}

func TestCreateUptrendsTableActive(t *testing.T) {
	result := &uptrends.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixUptrends),
	}

	table := createUptrendsTable(testIPUptrends, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Uptrends | Host: "+testIPUptrends, table.GetCell(0, 0).Text)
}

func TestCreateUptrendsTableNoMatch(t *testing.T) {
	table := createUptrendsTable(testIPUptrends, &uptrends.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderUptrends+testIPUptrends, table.GetCell(0, 0).Text)
	require.Equal(t, " No Uptrends prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestUptrendsActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createUptrendsTable(testIPUptrends, &uptrends.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixUptrends),
	}, false)

	addActiveIndicatorToTable(table, providerUptrends)

	require.Equal(t, " ▶ Uptrends | Host: "+testIPUptrends, table.GetCell(0, 0).Text)
}
