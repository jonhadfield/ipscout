package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/datadog"
	"github.com/stretchr/testify/require"
)

const (
	testIPDatadog     = "3.233.144.1"
	testPrefixDatadog = "3.233.144.0/20"
)

func TestCreateDatadogTable(t *testing.T) {
	result := &datadog.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixDatadog),
	}

	table := createDatadogTable(testIPDatadog, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Datadog | Host: "+testIPDatadog, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixDatadog, table.GetCell(1, 1).Text)
}

func TestCreateDatadogTableActiveState(t *testing.T) {
	result := &datadog.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixDatadog),
	}

	table := createDatadogTable(testIPDatadog, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Datadog | Host: "+testIPDatadog, table.GetCell(0, 0).Text)
}

func TestCreateDatadogTableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in Datadog ranges.
	table := createDatadogTable(testIPExample, &datadog.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Datadog | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Datadog ranges", table.GetCell(1, 0).Text)
}
