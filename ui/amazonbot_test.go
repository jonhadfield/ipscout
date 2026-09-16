package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/amazonbot"
	"github.com/stretchr/testify/require"
)

const (
	testIPAmazonbot     = "192.0.2.1"
	testPrefixAmazonbot = "192.0.2.0/24"
	testHeaderAmazonbot = " Amazonbot | Host: "
)

func TestCreateAmazonbotTable(t *testing.T) {
	result := &amazonbot.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixAmazonbot),
		Lists:  []string{"amazonbot"},
	}

	table := createAmazonbotTable(testIPAmazonbot, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderAmazonbot+testIPAmazonbot, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixAmazonbot, table.GetCell(1, 1).Text)
	require.Equal(t, " Lists", table.GetCell(2, 0).Text)
	require.Equal(t, "amazonbot", table.GetCell(2, 1).Text)
}

func TestCreateAmazonbotTableNoMatch(t *testing.T) {
	table := createAmazonbotTable(testIPAmazonbot, &amazonbot.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderAmazonbot+testIPAmazonbot, table.GetCell(0, 0).Text)
	require.Equal(t, " No Amazonbot prefix found", table.GetCell(1, 0).Text)
}
