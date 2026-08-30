package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/render"
	"github.com/stretchr/testify/require"
)

const (
	testIPRender     = "216.24.60.1"
	testPrefixRender = "216.24.60.0/24"
)

func TestCreateRenderTable(t *testing.T) {
	result := &render.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixRender),
	}

	table := createRenderTable(testIPRender, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Render | Host: "+testIPRender, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixRender, table.GetCell(1, 1).Text)
}

func TestCreateRenderTableActiveState(t *testing.T) {
	result := &render.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixRender),
	}

	table := createRenderTable(testIPRender, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Render | Host: "+testIPRender, table.GetCell(0, 0).Text)
}

func TestCreateRenderTableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in Render ranges.
	table := createRenderTable(testIPExample, &render.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Render | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Render ranges", table.GetCell(1, 0).Text)
}
