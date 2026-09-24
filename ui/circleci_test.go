package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/circleci"
	"github.com/stretchr/testify/require"
)

const (
	testIPCircleCI     = "192.0.2.1"
	testPrefixCircleCI = "192.0.2.0/24"
)

func TestCreateCircleCITable(t *testing.T) {
	result := &circleci.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCircleCI),
	}

	table := createCircleCITable(testIPCircleCI, result, false)
	require.NotNil(t, table)

	require.Equal(t, " CircleCI | Host: "+testIPCircleCI, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixCircleCI, table.GetCell(1, 1).Text)
}

func TestCreateCircleCITableActiveState(t *testing.T) {
	result := &circleci.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCircleCI),
	}

	table := createCircleCITable(testIPCircleCI, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ CircleCI | Host: "+testIPCircleCI, table.GetCell(0, 0).Text)
}

func TestCreateCircleCITableNoMatch(t *testing.T) {
	table := createCircleCITable(testIPExample, &circleci.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " CircleCI | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in CircleCI ranges", table.GetCell(1, 0).Text)
}
