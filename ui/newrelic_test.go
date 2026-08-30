package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/newrelic"
	"github.com/stretchr/testify/require"
)

const (
	testIPNewRelic     = "192.0.2.1"
	testPrefixNewRelic = "192.0.2.1/32"
	testHeaderNewRelic = " New Relic | Host: "
)

func TestCreateNewRelicTable(t *testing.T) {
	result := &newrelic.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixNewRelic),
	}

	table := createNewRelicTable(testIPNewRelic, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderNewRelic+testIPNewRelic, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixNewRelic, table.GetCell(1, 1).Text)
}

func TestCreateNewRelicTableActive(t *testing.T) {
	result := &newrelic.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixNewRelic),
	}

	table := createNewRelicTable(testIPNewRelic, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ New Relic | Host: "+testIPNewRelic, table.GetCell(0, 0).Text)
}

func TestCreateNewRelicTableNoMatch(t *testing.T) {
	table := createNewRelicTable(testIPNewRelic, &newrelic.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderNewRelic+testIPNewRelic, table.GetCell(0, 0).Text)
	require.Equal(t, " No New Relic prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestNewRelicActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createNewRelicTable(testIPNewRelic, &newrelic.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixNewRelic),
	}, false)

	addActiveIndicatorToTable(table, providerNewRelic)

	require.Equal(t, " ▶ New Relic | Host: "+testIPNewRelic, table.GetCell(0, 0).Text)
}
