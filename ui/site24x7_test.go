package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/site24x7"
	"github.com/stretchr/testify/require"
)

const (
	testIPSite24x7     = "192.0.2.1"
	testPrefixSite24x7 = "192.0.2.1/32"
	testHeaderSite24x7 = " Site24x7 | Host: "
)

func TestCreateSite24x7Table(t *testing.T) {
	result := &site24x7.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixSite24x7),
	}

	table := createSite24x7Table(testIPSite24x7, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderSite24x7+testIPSite24x7, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixSite24x7, table.GetCell(1, 1).Text)
}

func TestCreateSite24x7TableActive(t *testing.T) {
	result := &site24x7.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixSite24x7),
	}

	table := createSite24x7Table(testIPSite24x7, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Site24x7 | Host: "+testIPSite24x7, table.GetCell(0, 0).Text)
}

func TestCreateSite24x7TableNoMatch(t *testing.T) {
	table := createSite24x7Table(testIPSite24x7, &site24x7.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderSite24x7+testIPSite24x7, table.GetCell(0, 0).Text)
	require.Equal(t, " No Site24x7 prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestSite24x7ActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createSite24x7Table(testIPSite24x7, &site24x7.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixSite24x7),
	}, false)

	addActiveIndicatorToTable(table, providerSite24x7)

	require.Equal(t, " ▶ Site24x7 | Host: "+testIPSite24x7, table.GetCell(0, 0).Text)
}
