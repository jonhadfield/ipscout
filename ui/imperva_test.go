package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/imperva"
	"github.com/stretchr/testify/require"
)

const (
	testIPImperva     = "45.64.64.1"
	testPrefixImperva = "45.64.64.0/22"
)

func TestCreateImpervaTable(t *testing.T) {
	result := &imperva.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixImperva),
	}

	table := createImpervaTable(testIPImperva, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Imperva | Host: "+testIPImperva, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixImperva, table.GetCell(1, 1).Text)
}

func TestCreateImpervaTableActiveState(t *testing.T) {
	result := &imperva.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixImperva),
	}

	table := createImpervaTable(testIPImperva, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Imperva | Host: "+testIPImperva, table.GetCell(0, 0).Text)
}

func TestCreateImpervaTableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in Imperva ranges.
	table := createImpervaTable(testIPExample, &imperva.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Imperva | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Imperva ranges", table.GetCell(1, 0).Text)
}
