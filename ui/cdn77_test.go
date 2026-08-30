package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/cdn77"
	"github.com/stretchr/testify/require"
)

const (
	testIPCDN77     = "185.152.64.1"
	testPrefixCDN77 = "185.152.64.0/22"
)

func TestCreateCDN77Table(t *testing.T) {
	result := &cdn77.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCDN77),
	}

	table := createCDN77Table(testIPCDN77, result, false)
	require.NotNil(t, table)

	require.Equal(t, " CDN77 | Host: "+testIPCDN77, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixCDN77, table.GetCell(1, 1).Text)
}

func TestCreateCDN77TableActiveState(t *testing.T) {
	result := &cdn77.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCDN77),
	}

	table := createCDN77Table(testIPCDN77, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ CDN77 | Host: "+testIPCDN77, table.GetCell(0, 0).Text)
}

func TestCreateCDN77TableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in CDN77 ranges.
	table := createCDN77Table(testIPExample, &cdn77.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " CDN77 | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in CDN77 ranges", table.GetCell(1, 0).Text)
}
