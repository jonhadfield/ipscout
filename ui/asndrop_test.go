package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/providers/asndrop"
	"github.com/stretchr/testify/require"
)

func TestCreateASNDropTable(t *testing.T) {
	result := &asndrop.HostSearchResult{ASN: 64496, ASName: "EXAMPLE-AS"}

	table := createASNDropTable(testIPExample, result, false)

	require.NotNil(t, table)
	require.Equal(t, " ASN-DROP | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, "AS64496", table.GetCell(1, 1).Text)
	require.Equal(t, "EXAMPLE-AS", table.GetCell(2, 1).Text)
}

func TestCreateASNDropTableNoMatch(t *testing.T) {
	table := createASNDropTable(testIPExample, &asndrop.HostSearchResult{}, false)

	require.Equal(t, " AS not on ASN-DROP ", table.GetCell(1, 0).Text)
}
