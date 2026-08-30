package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/fastly"
	"github.com/stretchr/testify/require"
)

const (
	testIPFastly     = "151.101.0.1"
	testPrefixFastly = "151.101.0.0/16"
)

func TestCreateFastlyTable(t *testing.T) {
	result := &fastly.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixFastly),
	}

	table := createFastlyTable(testIPFastly, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Fastly | Host: "+testIPFastly, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixFastly, table.GetCell(1, 1).Text)
}

func TestCreateFastlyTableActiveState(t *testing.T) {
	result := &fastly.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixFastly),
	}

	table := createFastlyTable(testIPFastly, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Fastly | Host: "+testIPFastly, table.GetCell(0, 0).Text)
}

func TestCreateFastlyTableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in Fastly ranges.
	table := createFastlyTable(testIPExample, &fastly.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Fastly | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Fastly ranges", table.GetCell(1, 0).Text)
}
