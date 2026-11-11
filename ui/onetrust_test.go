package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/onetrust"
	"github.com/stretchr/testify/require"
)

const (
	testIPOneTrust     = "20.103.218.56"
	testPrefixOneTrust = "20.103.218.56/29"
	testHeaderOneTrust = " OneTrust | Host: "
)

func TestCreateOneTrustTable(t *testing.T) {
	result := &onetrust.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixOneTrust),
	}

	table := createOneTrustTable(testIPOneTrust, result, false)

	require.Equal(t, 2, table.GetRowCount())
	require.Equal(t, testHeaderOneTrust+testIPOneTrust, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixOneTrust, table.GetCell(1, 1).Text)
}

func TestCreateOneTrustTableActive(t *testing.T) {
	result := &onetrust.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixOneTrust),
	}

	table := createOneTrustTable(testIPOneTrust, result, true)

	require.Equal(t, 2, table.GetRowCount())
	require.Equal(t, " ▶ OneTrust | Host: "+testIPOneTrust, table.GetCell(0, 0).Text)
}

func TestCreateOneTrustTableNoMatch(t *testing.T) {
	table := createOneTrustTable(testIPOneTrust, &onetrust.HostSearchResult{}, false)

	require.Equal(t, 2, table.GetRowCount())
	require.Equal(t, testHeaderOneTrust+testIPOneTrust, table.GetCell(0, 0).Text)
	require.Equal(t, " No OneTrust prefix found", table.GetCell(1, 0).Text)
}

func TestOneTrustActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createOneTrustTable(testIPOneTrust, &onetrust.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixOneTrust),
	}, false)

	addActiveIndicatorToTable(table, providerOneTrust)

	require.Equal(t, " ▶ OneTrust | Host: "+testIPOneTrust, table.GetCell(0, 0).Text)
}
