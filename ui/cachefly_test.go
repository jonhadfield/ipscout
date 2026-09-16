package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/cachefly"
	"github.com/stretchr/testify/require"
)

const (
	testIPCacheFly     = "192.0.2.1"
	testPrefixCacheFly = "192.0.2.0/24"
)

func TestCreateCacheFlyTable(t *testing.T) {
	result := &cachefly.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCacheFly),
	}

	table := createCacheFlyTable(testIPCacheFly, result, false)
	require.NotNil(t, table)

	require.Equal(t, " CacheFly | Host: "+testIPCacheFly, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixCacheFly, table.GetCell(1, 1).Text)
}

func TestCreateCacheFlyTableActiveState(t *testing.T) {
	result := &cachefly.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCacheFly),
	}

	table := createCacheFlyTable(testIPCacheFly, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ CacheFly | Host: "+testIPCacheFly, table.GetCell(0, 0).Text)
}

func TestCreateCacheFlyTableNoMatch(t *testing.T) {
	table := createCacheFlyTable(testIPExample, &cachefly.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " CacheFly | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in CacheFly ranges", table.GetCell(1, 0).Text)
}
