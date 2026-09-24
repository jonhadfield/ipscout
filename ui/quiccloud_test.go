package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/quiccloud"
	"github.com/stretchr/testify/require"
)

const (
	testIPQuicCloud     = "192.0.2.1"
	testPrefixQuicCloud = "192.0.2.0/24"
)

func TestCreateQuicCloudTable(t *testing.T) {
	result := &quiccloud.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixQuicCloud),
	}

	table := createQuicCloudTable(testIPQuicCloud, result, false)
	require.NotNil(t, table)

	require.Equal(t, " QUIC.cloud | Host: "+testIPQuicCloud, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixQuicCloud, table.GetCell(1, 1).Text)
}

func TestCreateQuicCloudTableActiveState(t *testing.T) {
	result := &quiccloud.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixQuicCloud),
	}

	table := createQuicCloudTable(testIPQuicCloud, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ QUIC.cloud | Host: "+testIPQuicCloud, table.GetCell(0, 0).Text)
}

func TestCreateQuicCloudTableNoMatch(t *testing.T) {
	table := createQuicCloudTable(testIPExample, &quiccloud.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " QUIC.cloud | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in QUIC.cloud ranges", table.GetCell(1, 0).Text)
}
