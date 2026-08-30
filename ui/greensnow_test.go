package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/greensnow"
	"github.com/stretchr/testify/require"
)

const (
	testIPGreenSnow     = "192.0.2.1"
	testPrefixGreenSnow = "192.0.2.1/32"
	testHeaderGreenSnow = " GreenSnow | Host: "
)

func TestCreateGreenSnowTable(t *testing.T) {
	result := &greensnow.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixGreenSnow),
	}

	table := createGreenSnowTable(testIPGreenSnow, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderGreenSnow+testIPGreenSnow, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixGreenSnow, table.GetCell(1, 1).Text)
}

func TestCreateGreenSnowTableActive(t *testing.T) {
	result := &greensnow.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixGreenSnow),
	}

	table := createGreenSnowTable(testIPGreenSnow, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ GreenSnow | Host: "+testIPGreenSnow, table.GetCell(0, 0).Text)
}

func TestCreateGreenSnowTableNoMatch(t *testing.T) {
	table := createGreenSnowTable(testIPGreenSnow, &greensnow.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderGreenSnow+testIPGreenSnow, table.GetCell(0, 0).Text)
	require.Equal(t, " No GreenSnow prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestGreenSnowActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createGreenSnowTable(testIPGreenSnow, &greensnow.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixGreenSnow),
	}, false)

	addActiveIndicatorToTable(table, providerGreenSnow)

	require.Equal(t, " ▶ GreenSnow | Host: "+testIPGreenSnow, table.GetCell(0, 0).Text)
}
