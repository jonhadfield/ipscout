package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/ipsum"
	"github.com/stretchr/testify/require"
)

const (
	testIPIPsum     = "192.0.2.1"
	testPrefixIPsum = "192.0.2.0/24"
)

func TestCreateIPsumTable(t *testing.T) {
	result := &ipsum.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixIPsum),
	}

	table := createIPsumTable(testIPIPsum, result, false)
	require.NotNil(t, table)

	require.Equal(t, " IPsum | Host: "+testIPIPsum, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixIPsum, table.GetCell(1, 1).Text)
}

func TestCreateIPsumTableActiveState(t *testing.T) {
	result := &ipsum.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixIPsum),
	}

	table := createIPsumTable(testIPIPsum, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ IPsum | Host: "+testIPIPsum, table.GetCell(0, 0).Text)
}

func TestCreateIPsumTableNoMatch(t *testing.T) {
	table := createIPsumTable(testIPExample, &ipsum.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " IPsum | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in IPsum ranges", table.GetCell(1, 0).Text)
}
