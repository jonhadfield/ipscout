package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/emergingthreats"
	"github.com/stretchr/testify/require"
)

const (
	testIPEmergingThreats     = "198.51.100.42"
	testPrefixEmergingThreats = "198.51.100.42/32"
	testHeaderEmergingThreats = " Emerging Threats | Host: "
)

func TestCreateEmergingThreatsTable(t *testing.T) {
	result := &emergingthreats.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixEmergingThreats),
	}

	table := createEmergingThreatsTable(testIPEmergingThreats, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderEmergingThreats+testIPEmergingThreats, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixEmergingThreats, table.GetCell(1, 1).Text)
	require.Equal(t, " List", table.GetCell(2, 0).Text)
	require.Equal(t, "compromised IPs", table.GetCell(2, 1).Text)
}

func TestCreateEmergingThreatsTableActive(t *testing.T) {
	result := &emergingthreats.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixEmergingThreats),
	}

	table := createEmergingThreatsTable(testIPEmergingThreats, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Emerging Threats | Host: "+testIPEmergingThreats, table.GetCell(0, 0).Text)
}

func TestCreateEmergingThreatsTableNoMatch(t *testing.T) {
	table := createEmergingThreatsTable(testIPEmergingThreats, &emergingthreats.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderEmergingThreats+testIPEmergingThreats, table.GetCell(0, 0).Text)
	require.Equal(t, " No Emerging Threats prefix found", table.GetCell(1, 0).Text)
}
