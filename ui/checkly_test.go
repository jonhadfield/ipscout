package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/checkly"
	"github.com/stretchr/testify/require"
)

const (
	testIPCheckly     = "192.0.2.1"
	testPrefixCheckly = "192.0.2.1/32"
	testHeaderCheckly = " Checkly | Host: "
)

func TestCreateChecklyTable(t *testing.T) {
	result := &checkly.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCheckly),
	}

	table := createChecklyTable(testIPCheckly, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderCheckly+testIPCheckly, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixCheckly, table.GetCell(1, 1).Text)
}

func TestCreateChecklyTableActive(t *testing.T) {
	result := &checkly.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCheckly),
	}

	table := createChecklyTable(testIPCheckly, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Checkly | Host: "+testIPCheckly, table.GetCell(0, 0).Text)
}

func TestCreateChecklyTableNoMatch(t *testing.T) {
	table := createChecklyTable(testIPCheckly, &checkly.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderCheckly+testIPCheckly, table.GetCell(0, 0).Text)
	require.Equal(t, " No Checkly prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestChecklyActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createChecklyTable(testIPCheckly, &checkly.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCheckly),
	}, false)

	addActiveIndicatorToTable(table, providerCheckly)

	require.Equal(t, " ▶ Checkly | Host: "+testIPCheckly, table.GetCell(0, 0).Text)
}
