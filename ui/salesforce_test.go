package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/salesforce"
	"github.com/stretchr/testify/require"
)

const (
	testIPSalesforce     = "192.0.2.1"
	testPrefixSalesforce = "192.0.2.0/24"
)

func TestCreateSalesforceTable(t *testing.T) {
	result := &salesforce.HostSearchResult{
		Prefix:   netip.MustParsePrefix(testPrefixSalesforce),
		Region:   "us-west-2",
		Provider: "aws",
	}

	table := createSalesforceTable(testIPSalesforce, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Salesforce | Host: "+testIPSalesforce, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixSalesforce, table.GetCell(1, 1).Text)
	require.Equal(t, " Region", table.GetCell(2, 0).Text)
	require.Equal(t, "us-west-2", table.GetCell(2, 1).Text)
	require.Equal(t, " Provider", table.GetCell(3, 0).Text)
	require.Equal(t, "aws", table.GetCell(3, 1).Text)
}

func TestCreateSalesforceTableActiveState(t *testing.T) {
	result := &salesforce.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixSalesforce),
	}

	table := createSalesforceTable(testIPSalesforce, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Salesforce | Host: "+testIPSalesforce, table.GetCell(0, 0).Text)
}

func TestCreateSalesforceTableNoMatch(t *testing.T) {
	table := createSalesforceTable(testIPExample, &salesforce.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Salesforce | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Salesforce ranges", table.GetCell(1, 0).Text)
}
