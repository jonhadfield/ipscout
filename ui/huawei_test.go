package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/huawei"
	"github.com/stretchr/testify/require"
)

const (
	testIPHuawei     = "192.0.2.1"
	testPrefixHuawei = "192.0.2.0/24"
)

func TestCreateHuaweiTable(t *testing.T) {
	result := &huawei.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixHuawei),
	}

	table := createHuaweiTable(testIPHuawei, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Huawei Cloud | Host: "+testIPHuawei, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixHuawei, table.GetCell(1, 1).Text)
}

func TestCreateHuaweiTableActiveState(t *testing.T) {
	result := &huawei.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixHuawei),
	}

	table := createHuaweiTable(testIPHuawei, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Huawei Cloud | Host: "+testIPHuawei, table.GetCell(0, 0).Text)
}

func TestCreateHuaweiTableNoMatch(t *testing.T) {
	table := createHuaweiTable(testIPExample, &huawei.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Huawei Cloud | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Huawei Cloud ranges", table.GetCell(1, 0).Text)
}
