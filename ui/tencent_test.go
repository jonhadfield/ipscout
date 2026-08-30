package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/tencent"
	"github.com/stretchr/testify/require"
)

const (
	testIPTencent     = "43.128.0.1"
	testPrefixTencent = "43.128.0.0/16"
)

func TestCreateTencentTable(t *testing.T) {
	result := &tencent.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixTencent),
	}

	table := createTencentTable(testIPTencent, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Tencent Cloud | Host: "+testIPTencent, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixTencent, table.GetCell(1, 1).Text)
}

func TestCreateTencentTableActiveState(t *testing.T) {
	result := &tencent.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixTencent),
	}

	table := createTencentTable(testIPTencent, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Tencent Cloud | Host: "+testIPTencent, table.GetCell(0, 0).Text)
}

func TestCreateTencentTableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in Tencent Cloud ranges.
	table := createTencentTable(testIPExample, &tencent.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Tencent Cloud | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Tencent Cloud ranges", table.GetCell(1, 0).Text)
}
