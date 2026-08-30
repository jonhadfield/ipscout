package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/cymru"
	"github.com/stretchr/testify/require"
)

const (
	testIPCymru     = "0.0.0.1"
	testPrefixCymru = "0.0.0.0/8"
	testHeaderCymru = " Team Cymru Bogons | Host: "
)

func TestCreateCymruTable(t *testing.T) {
	lastUpdated := time.Date(2026, 8, 29, 8, 55, 1, 0, time.UTC)
	result := &cymru.HostSearchResult{
		Prefix:      netip.MustParsePrefix(testPrefixCymru),
		LastUpdated: lastUpdated,
	}

	table := createCymruTable(testIPCymru, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderCymru+testIPCymru, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixCymru, table.GetCell(1, 1).Text)
	require.Equal(t, " Last Updated", table.GetCell(2, 0).Text)
	require.Equal(t, lastUpdated.String(), table.GetCell(2, 1).Text)
}

func TestCreateCymruTableActive(t *testing.T) {
	result := &cymru.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCymru),
	}

	table := createCymruTable(testIPCymru, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Team Cymru Bogons | Host: "+testIPCymru, table.GetCell(0, 0).Text)
}

func TestCreateCymruTableNoMatch(t *testing.T) {
	table := createCymruTable(testIPCymru, &cymru.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderCymru+testIPCymru, table.GetCell(0, 0).Text)
	require.Equal(t, " No Team Cymru Bogons prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestCymruActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createCymruTable(testIPCymru, &cymru.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCymru),
	}, false)

	addActiveIndicatorToTable(table, providerCymru)

	require.Equal(t, " ▶ Team Cymru Bogons | Host: "+testIPCymru, table.GetCell(0, 0).Text)
}
