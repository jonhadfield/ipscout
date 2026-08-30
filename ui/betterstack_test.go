package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/betterstack"
	"github.com/stretchr/testify/require"
)

const (
	testIPBetterStack     = "192.0.2.1"
	testPrefixBetterStack = "192.0.2.1/32"
	testHeaderBetterStack = " Better Stack | Host: "
)

func TestCreateBetterStackTable(t *testing.T) {
	result := &betterstack.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixBetterStack),
	}

	table := createBetterStackTable(testIPBetterStack, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderBetterStack+testIPBetterStack, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixBetterStack, table.GetCell(1, 1).Text)
}

func TestCreateBetterStackTableActive(t *testing.T) {
	result := &betterstack.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixBetterStack),
	}

	table := createBetterStackTable(testIPBetterStack, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Better Stack | Host: "+testIPBetterStack, table.GetCell(0, 0).Text)
}

func TestCreateBetterStackTableNoMatch(t *testing.T) {
	table := createBetterStackTable(testIPBetterStack, &betterstack.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderBetterStack+testIPBetterStack, table.GetCell(0, 0).Text)
	require.Equal(t, " No Better Stack prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestBetterStackActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createBetterStackTable(testIPBetterStack, &betterstack.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixBetterStack),
	}, false)

	addActiveIndicatorToTable(table, providerBetterStack)

	require.Equal(t, " ▶ Better Stack | Host: "+testIPBetterStack, table.GetCell(0, 0).Text)
}
