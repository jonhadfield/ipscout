package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/tor"
	"github.com/stretchr/testify/require"
)

const (
	testIPTor     = "192.0.2.1"
	testPrefixTor = "192.0.2.1/32"
	testHeaderTor = " Tor Exit Node | Host: "
)

func TestCreateTorTable(t *testing.T) {
	result := &tor.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixTor),
	}

	table := createTorTable(testIPTor, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderTor+testIPTor, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixTor, table.GetCell(1, 1).Text)
}

func TestCreateTorTableActive(t *testing.T) {
	result := &tor.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixTor),
	}

	table := createTorTable(testIPTor, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Tor Exit Node | Host: "+testIPTor, table.GetCell(0, 0).Text)
}

func TestCreateTorTableNoMatch(t *testing.T) {
	table := createTorTable(testIPTor, &tor.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderTor+testIPTor, table.GetCell(0, 0).Text)
	require.Equal(t, " No Tor Exit Node prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestTorActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createTorTable(testIPTor, &tor.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixTor),
	}, false)

	addActiveIndicatorToTable(table, providerTor)

	require.Equal(t, " ▶ Tor Exit Node | Host: "+testIPTor, table.GetCell(0, 0).Text)
}
