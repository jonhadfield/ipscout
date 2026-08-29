package ui

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/cymru"
	"github.com/jonhadfield/ipscout/providers/greensnow"
	"github.com/stretchr/testify/require"
)

const (
	testBogonPrefix     = "0.0.0.0/8"
	testGreenSnowPrefix = "192.0.2.1/32"
)

func TestCreateCymruTable(t *testing.T) {
	result := &cymru.HostSearchResult{
		Prefix:      netip.MustParsePrefix(testBogonPrefix),
		LastUpdated: time.Date(2026, 8, 29, 8, 55, 1, 0, time.UTC),
	}

	table := createCymruTable(testIPExample, result, false)
	require.NotNil(t, table)
	require.Contains(t, table.GetCell(0, 0).Text, "Team Cymru Bogons")
	require.Contains(t, table.GetCell(1, 1).Text, testBogonPrefix)
}

func TestCreateCymruTableNoMatch(t *testing.T) {
	table := createCymruTable(testIPExample, &cymru.HostSearchResult{}, false)
	require.NotNil(t, table)
	require.Contains(t, table.GetCell(1, 0).Text, "No Team Cymru Bogons prefix found")
}

func TestCreateGreenSnowTable(t *testing.T) {
	result := &greensnow.HostSearchResult{Prefix: netip.MustParsePrefix(testGreenSnowPrefix)}

	table := createGreenSnowTable(testIPExample, result, false)
	require.NotNil(t, table)
	require.Contains(t, table.GetCell(0, 0).Text, "GreenSnow")
	require.Contains(t, table.GetCell(1, 1).Text, testGreenSnowPrefix)
}

func TestCreateGreenSnowTableNoMatch(t *testing.T) {
	table := createGreenSnowTable(testIPExample, &greensnow.HostSearchResult{}, false)
	require.NotNil(t, table)
	require.Contains(t, table.GetCell(1, 0).Text, "No GreenSnow prefix found")
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. Both of these have one, so they need
// an explicit case in the switch; without it the marker is never added.
func TestActiveIndicatorAddedForMixedCaseHeaders(t *testing.T) {
	cymruTable := createCymruTable(testIPExample, &cymru.HostSearchResult{
		Prefix: netip.MustParsePrefix(testBogonPrefix),
	}, false)
	addActiveIndicatorToTable(cymruTable, providerCymru)
	require.True(t, strings.Contains(cymruTable.GetCell(0, 0).Text, "▶"),
		"cymru header did not gain the active marker: %q", cymruTable.GetCell(0, 0).Text)

	greenTable := createGreenSnowTable(testIPExample, &greensnow.HostSearchResult{
		Prefix: netip.MustParsePrefix(testGreenSnowPrefix),
	}, false)
	addActiveIndicatorToTable(greenTable, providerGreenSnow)
	require.True(t, strings.Contains(greenTable.GetCell(0, 0).Text, "▶"),
		"greensnow header did not gain the active marker: %q", greenTable.GetCell(0, 0).Text)
}

// The panels render their own active header when isActive is set, which is a
// separate path from addActiveIndicatorToTable rewriting an existing one.
func TestCreateCymruTableActiveState(t *testing.T) {
	result := &cymru.HostSearchResult{Prefix: netip.MustParsePrefix(testBogonPrefix)}

	table := createCymruTable(testIPExample, result, true)
	require.NotNil(t, table)
	require.Contains(t, table.GetCell(0, 0).Text, "▶ Team Cymru Bogons")
}

func TestCreateGreenSnowTableActiveState(t *testing.T) {
	result := &greensnow.HostSearchResult{Prefix: netip.MustParsePrefix(testGreenSnowPrefix)}

	table := createGreenSnowTable(testIPExample, result, true)
	require.NotNil(t, table)
	require.Contains(t, table.GetCell(0, 0).Text, "▶ GreenSnow")
}
