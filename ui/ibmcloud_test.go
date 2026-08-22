package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/ibmcloud"
	"github.com/stretchr/testify/require"
)

const (
	testIPIBMCloud     = "169.59.0.1"
	testPrefixIBMCloud = "169.59.0.0/16"
)

func TestCreateIBMCloudTable(t *testing.T) {
	result := &ibmcloud.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixIBMCloud),
	}

	table := createIBMCloudTable(testIPIBMCloud, result, false)
	require.NotNil(t, table)

	require.Equal(t, " IBM Cloud | Host: "+testIPIBMCloud, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixIBMCloud, table.GetCell(1, 1).Text)
}

func TestCreateIBMCloudTableActiveState(t *testing.T) {
	result := &ibmcloud.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixIBMCloud),
	}

	table := createIBMCloudTable(testIPIBMCloud, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ IBM Cloud | Host: "+testIPIBMCloud, table.GetCell(0, 0).Text)
}

func TestCreateIBMCloudTableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in IBM Cloud ranges.
	table := createIBMCloudTable(testIPExample, &ibmcloud.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " IBM Cloud | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in IBM Cloud ranges", table.GetCell(1, 0).Text)
}
