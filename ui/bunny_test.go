package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/bunny"
	"github.com/stretchr/testify/require"
)

const (
	testIPBunny     = "89.187.162.1"
	testPrefixBunny = "89.187.162.0/24"
)

func TestCreateBunnyCDNTable(t *testing.T) {
	result := &bunny.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixBunny),
	}

	table := createBunnyTable(testIPBunny, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Bunny CDN | Host: "+testIPBunny, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixBunny, table.GetCell(1, 1).Text)
}

func TestCreateBunnyCDNTableActiveState(t *testing.T) {
	result := &bunny.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixBunny),
	}

	table := createBunnyTable(testIPBunny, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Bunny CDN | Host: "+testIPBunny, table.GetCell(0, 0).Text)
}

func TestCreateBunnyCDNTableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in Bunny CDN ranges.
	table := createBunnyTable(testIPExample, &bunny.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Bunny CDN | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Bunny CDN ranges", table.GetCell(1, 0).Text)
}
