package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/feodo"
	"github.com/stretchr/testify/require"
)

const (
	testIPFeodo     = "192.0.2.1"
	testPrefixFeodo = "192.0.2.1/32"
	testHeaderFeodo = " Feodo Tracker | Host: "
)

func TestCreateFeodoTable(t *testing.T) {
	result := &feodo.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixFeodo),
	}

	table := createFeodoTable(testIPFeodo, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderFeodo+testIPFeodo, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixFeodo, table.GetCell(1, 1).Text)
}

func TestCreateFeodoTableActive(t *testing.T) {
	result := &feodo.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixFeodo),
	}

	table := createFeodoTable(testIPFeodo, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Feodo Tracker | Host: "+testIPFeodo, table.GetCell(0, 0).Text)
}

func TestCreateFeodoTableNoMatch(t *testing.T) {
	table := createFeodoTable(testIPFeodo, &feodo.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderFeodo+testIPFeodo, table.GetCell(0, 0).Text)
	require.Equal(t, " No Feodo Tracker prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestFeodoActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createFeodoTable(testIPFeodo, &feodo.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixFeodo),
	}, false)

	addActiveIndicatorToTable(table, providerFeodo)

	require.Equal(t, " ▶ Feodo Tracker | Host: "+testIPFeodo, table.GetCell(0, 0).Text)
}
