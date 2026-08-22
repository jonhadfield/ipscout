package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/atlassian"
	"github.com/stretchr/testify/require"
)

const (
	testIPAtlassian     = "104.192.136.1"
	testPrefixAtlassian = "104.192.136.0/21"
)

func TestCreateAtlassianTable(t *testing.T) {
	result := &atlassian.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixAtlassian),
	}

	table := createAtlassianTable(testIPAtlassian, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Atlassian | Host: "+testIPAtlassian, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixAtlassian, table.GetCell(1, 1).Text)
}

func TestCreateAtlassianTableActiveState(t *testing.T) {
	result := &atlassian.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixAtlassian),
	}

	table := createAtlassianTable(testIPAtlassian, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Atlassian | Host: "+testIPAtlassian, table.GetCell(0, 0).Text)
}

func TestCreateAtlassianTableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in Atlassian ranges.
	table := createAtlassianTable(testIPExample, &atlassian.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Atlassian | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Atlassian ranges", table.GetCell(1, 0).Text)
}
