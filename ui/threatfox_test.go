package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/threatfox"
	"github.com/stretchr/testify/require"
)

const (
	testIPThreatFox     = "192.0.2.1"
	testPrefixThreatFox = "192.0.2.0/24"
)

func TestCreateThreatFoxTable(t *testing.T) {
	result := &threatfox.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixThreatFox),
	}

	table := createThreatFoxTable(testIPThreatFox, result, false)
	require.NotNil(t, table)

	require.Equal(t, " ThreatFox | Host: "+testIPThreatFox, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixThreatFox, table.GetCell(1, 1).Text)
}

func TestCreateThreatFoxTableActiveState(t *testing.T) {
	result := &threatfox.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixThreatFox),
	}

	table := createThreatFoxTable(testIPThreatFox, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ ThreatFox | Host: "+testIPThreatFox, table.GetCell(0, 0).Text)
}

func TestCreateThreatFoxTableNoMatch(t *testing.T) {
	table := createThreatFoxTable(testIPExample, &threatfox.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " ThreatFox | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in ThreatFox ranges", table.GetCell(1, 0).Text)
}
