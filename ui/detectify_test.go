package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/detectify"
	"github.com/stretchr/testify/require"
)

const (
	testIPDetectify     = "192.0.2.1"
	testPrefixDetectify = "192.0.2.1/32"
	testHeaderDetectify = " Detectify | Host: "
)

func TestCreateDetectifyTable(t *testing.T) {
	result := &detectify.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixDetectify),
	}

	table := createDetectifyTable(testIPDetectify, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderDetectify+testIPDetectify, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixDetectify, table.GetCell(1, 1).Text)
}

func TestCreateDetectifyTableActive(t *testing.T) {
	result := &detectify.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixDetectify),
	}

	table := createDetectifyTable(testIPDetectify, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Detectify | Host: "+testIPDetectify, table.GetCell(0, 0).Text)
}

func TestCreateDetectifyTableNoMatch(t *testing.T) {
	table := createDetectifyTable(testIPDetectify, &detectify.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderDetectify+testIPDetectify, table.GetCell(0, 0).Text)
	require.Equal(t, " No Detectify prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestDetectifyActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createDetectifyTable(testIPDetectify, &detectify.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixDetectify),
	}, false)

	addActiveIndicatorToTable(table, providerDetectify)

	require.Equal(t, " ▶ Detectify | Host: "+testIPDetectify, table.GetCell(0, 0).Text)
}
