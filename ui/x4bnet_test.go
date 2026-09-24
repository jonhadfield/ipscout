package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/x4bnet"
	"github.com/stretchr/testify/require"
)

const (
	testIPX4BNet     = "192.0.2.1"
	testPrefixX4BNet = "192.0.2.0/24"
)

func TestCreateX4BNetTable(t *testing.T) {
	result := &x4bnet.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixX4BNet),
	}

	table := createX4BNetTable(testIPX4BNet, result, false)
	require.NotNil(t, table)

	require.Equal(t, " X4BNet | Host: "+testIPX4BNet, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixX4BNet, table.GetCell(1, 1).Text)
}

func TestCreateX4BNetTableActiveState(t *testing.T) {
	result := &x4bnet.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixX4BNet),
	}

	table := createX4BNetTable(testIPX4BNet, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ X4BNet | Host: "+testIPX4BNet, table.GetCell(0, 0).Text)
}

func TestCreateX4BNetTableNoMatch(t *testing.T) {
	table := createX4BNetTable(testIPExample, &x4bnet.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " X4BNet | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in X4BNet ranges", table.GetCell(1, 0).Text)
}
