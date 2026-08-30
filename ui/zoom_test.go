package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/zoom"
	"github.com/stretchr/testify/require"
)

const (
	testIPZoom     = "192.0.2.1"
	testPrefixZoom = "192.0.2.1/32"
	testHeaderZoom = " Zoom | Host: "
)

func TestCreateZoomTable(t *testing.T) {
	result := &zoom.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixZoom),
	}

	table := createZoomTable(testIPZoom, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderZoom+testIPZoom, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixZoom, table.GetCell(1, 1).Text)
}

func TestCreateZoomTableActive(t *testing.T) {
	result := &zoom.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixZoom),
	}

	table := createZoomTable(testIPZoom, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Zoom | Host: "+testIPZoom, table.GetCell(0, 0).Text)
}

func TestCreateZoomTableNoMatch(t *testing.T) {
	table := createZoomTable(testIPZoom, &zoom.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderZoom+testIPZoom, table.GetCell(0, 0).Text)
	require.Equal(t, " No Zoom prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestZoomActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createZoomTable(testIPZoom, &zoom.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixZoom),
	}, false)

	addActiveIndicatorToTable(table, providerZoom)

	require.Equal(t, " ▶ Zoom | Host: "+testIPZoom, table.GetCell(0, 0).Text)
}
