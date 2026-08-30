package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/cinsscore"
	"github.com/stretchr/testify/require"
)

const (
	testIPCINSScore     = "198.51.100.42"
	testPrefixCINSScore = "198.51.100.42/32"
	testHeaderCINSScore = " CINS Army List | Host: "
)

func TestCreateCINSScoreTable(t *testing.T) {
	result := &cinsscore.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCINSScore),
	}

	table := createCINSScoreTable(testIPCINSScore, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderCINSScore+testIPCINSScore, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixCINSScore, table.GetCell(1, 1).Text)
}

func TestCreateCINSScoreTableActive(t *testing.T) {
	result := &cinsscore.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCINSScore),
	}

	table := createCINSScoreTable(testIPCINSScore, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ CINS Army List | Host: "+testIPCINSScore, table.GetCell(0, 0).Text)
}

func TestCreateCINSScoreTableNoMatch(t *testing.T) {
	table := createCINSScoreTable(testIPCINSScore, &cinsscore.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderCINSScore+testIPCINSScore, table.GetCell(0, 0).Text)
	require.Equal(t, " No CINS Army List prefix found", table.GetCell(1, 0).Text)
}
