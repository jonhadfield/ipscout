package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/updown"
	"github.com/stretchr/testify/require"
)

const (
	testIPUpdown     = "192.0.2.1"
	testPrefixUpdown = "192.0.2.1/32"
	testHeaderUpdown = " updown.io | Host: "
)

func TestCreateUpdownTable(t *testing.T) {
	result := &updown.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixUpdown),
	}

	table := createUpdownTable(testIPUpdown, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderUpdown+testIPUpdown, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixUpdown, table.GetCell(1, 1).Text)
}

func TestCreateUpdownTableActive(t *testing.T) {
	result := &updown.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixUpdown),
	}

	table := createUpdownTable(testIPUpdown, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ updown.io | Host: "+testIPUpdown, table.GetCell(0, 0).Text)
}

func TestCreateUpdownTableNoMatch(t *testing.T) {
	table := createUpdownTable(testIPUpdown, &updown.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderUpdown+testIPUpdown, table.GetCell(0, 0).Text)
	require.Equal(t, " No updown.io prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestUpdownActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createUpdownTable(testIPUpdown, &updown.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixUpdown),
	}, false)

	addActiveIndicatorToTable(table, providerUpdown)

	require.Equal(t, " ▶ updown.io | Host: "+testIPUpdown, table.GetCell(0, 0).Text)
}
