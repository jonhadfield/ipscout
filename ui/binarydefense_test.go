package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/binarydefense"
	"github.com/stretchr/testify/require"
)

const (
	testIPBinaryDefense     = "192.0.2.1"
	testPrefixBinaryDefense = "192.0.2.0/24"
)

func TestCreateBinaryDefenseTable(t *testing.T) {
	result := &binarydefense.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixBinaryDefense),
	}

	table := createBinaryDefenseTable(testIPBinaryDefense, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Binary Defense | Host: "+testIPBinaryDefense, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixBinaryDefense, table.GetCell(1, 1).Text)
}

func TestCreateBinaryDefenseTableActiveState(t *testing.T) {
	result := &binarydefense.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixBinaryDefense),
	}

	table := createBinaryDefenseTable(testIPBinaryDefense, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Binary Defense | Host: "+testIPBinaryDefense, table.GetCell(0, 0).Text)
}

func TestCreateBinaryDefenseTableNoMatch(t *testing.T) {
	table := createBinaryDefenseTable(testIPExample, &binarydefense.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Binary Defense | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Binary Defense ranges", table.GetCell(1, 0).Text)
}
