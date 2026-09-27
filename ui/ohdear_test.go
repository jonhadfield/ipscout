package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/ohdear"
	"github.com/stretchr/testify/require"
)

const (
	testIPOhDear     = "192.0.2.1"
	testPrefixOhDear = "192.0.2.0/24"
)

func TestCreateOhDearTable(t *testing.T) {
	result := &ohdear.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixOhDear),
	}

	table := createOhDearTable(testIPOhDear, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Oh Dear | Host: "+testIPOhDear, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixOhDear, table.GetCell(1, 1).Text)
}

func TestCreateOhDearTableActiveState(t *testing.T) {
	result := &ohdear.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixOhDear),
	}

	table := createOhDearTable(testIPOhDear, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Oh Dear | Host: "+testIPOhDear, table.GetCell(0, 0).Text)
}

func TestCreateOhDearTableNoMatch(t *testing.T) {
	table := createOhDearTable(testIPExample, &ohdear.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Oh Dear | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Oh Dear ranges", table.GetCell(1, 0).Text)
}
