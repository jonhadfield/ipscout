package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/providers/internetdb"
	"github.com/stretchr/testify/require"
)

func TestCreateInternetDBTable(t *testing.T) {
	result := &internetdb.HostSearchResult{
		Ports: []int{53, 443},
		Tags:  []string{"tor"},
		Vulns: []string{"CVE-2024-0001"},
	}

	table := createInternetDBTable(testIPExample, result, false)

	require.NotNil(t, table)
	require.Equal(t, " InternetDB | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " Open Ports", table.GetCell(1, 0).Text)
	require.Equal(t, "53, 443", table.GetCell(1, 1).Text)
	require.Equal(t, " Tags", table.GetCell(2, 0).Text)
	require.Equal(t, " Vulns", table.GetCell(3, 0).Text)
	require.Equal(t, "CVE-2024-0001", table.GetCell(3, 1).Text)
}

func TestCreateInternetDBTableActiveState(t *testing.T) {
	table := createInternetDBTable(testIPExample, &internetdb.HostSearchResult{Ports: []int{80}}, true)

	require.Equal(t, " ▶ InternetDB | Host: "+testIPExample, table.GetCell(0, 0).Text)
}

func TestCreateInternetDBTableNoData(t *testing.T) {
	table := createInternetDBTable(testIPExample, &internetdb.HostSearchResult{}, false)

	require.Equal(t, " No InternetDB data for this IP", table.GetCell(1, 0).Text)
}
