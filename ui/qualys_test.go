package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/qualys"
	"github.com/stretchr/testify/require"
)

const (
	testIPQualys     = "192.0.2.1"
	testPrefixQualys = "192.0.2.0/24"
)

func TestCreateQualysTable(t *testing.T) {
	result := &qualys.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixQualys),
	}

	table := createQualysTable(testIPQualys, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Qualys | Host: "+testIPQualys, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixQualys, table.GetCell(1, 1).Text)
}

func TestCreateQualysTableActiveState(t *testing.T) {
	result := &qualys.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixQualys),
	}

	table := createQualysTable(testIPQualys, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Qualys | Host: "+testIPQualys, table.GetCell(0, 0).Text)
}

func TestCreateQualysTableNoMatch(t *testing.T) {
	table := createQualysTable(testIPExample, &qualys.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Qualys | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Qualys ranges", table.GetCell(1, 0).Text)
}
