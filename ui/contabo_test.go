package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/contabo"
	"github.com/stretchr/testify/require"
)

const (
	testIPContabo     = "194.163.128.1"
	testPrefixContabo = "194.163.128.0/17"
)

func TestCreateContaboTable(t *testing.T) {
	result := &contabo.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixContabo),
	}

	table := createContaboTable(testIPContabo, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Contabo | Host: "+testIPContabo, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixContabo, table.GetCell(1, 1).Text)
}

func TestCreateContaboTableActiveState(t *testing.T) {
	result := &contabo.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixContabo),
	}

	table := createContaboTable(testIPContabo, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Contabo | Host: "+testIPContabo, table.GetCell(0, 0).Text)
}

func TestCreateContaboTableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in Contabo ranges.
	table := createContaboTable(testIPExample, &contabo.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Contabo | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Contabo ranges", table.GetCell(1, 0).Text)
}
