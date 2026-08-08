package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/akamai"
	"github.com/stretchr/testify/require"
)

const (
	testIPAkamai           = "23.32.0.5"
	testPrefixAkamai       = "23.32.0.0/11"
	akamaiHeaderPrefixText = " Akamai | Host: "
)

func TestCreateAkamaiTable(t *testing.T) {
	result := &akamai.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixAkamai),
	}

	table := createAkamaiTable(testIPAkamai, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	// header row
	header := table.GetCell(0, 0)
	require.NotNil(t, header)
	require.Equal(t, akamaiHeaderPrefixText+testIPAkamai, header.Text)

	// prefix row
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixAkamai, table.GetCell(1, 1).Text)

	// status row
	require.Equal(t, " Status", table.GetCell(2, 0).Text)
	require.Equal(t, "Akamai CDN", table.GetCell(2, 1).Text)
}

func TestCreateAkamaiTableNoMatch(t *testing.T) {
	result := &akamai.HostSearchResult{
		Prefix: netip.Prefix{}, // invalid prefix means no match
	}

	table := createAkamaiTable(testIPExample, result, false)
	require.NotNil(t, table)

	header := table.GetCell(0, 0)
	require.NotNil(t, header)
	require.Equal(t, akamaiHeaderPrefixText+testIPExample, header.Text)

	require.Equal(t, " No Akamai range found", table.GetCell(1, 0).Text)
}

func TestCreateAkamaiTableActiveState(t *testing.T) {
	result := &akamai.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixAkamai),
	}

	activeTable := createAkamaiTable(testIPAkamai, result, true)
	require.NotNil(t, activeTable)
	require.Equal(t, " ▶"+akamaiHeaderPrefixText+testIPAkamai, activeTable.GetCell(0, 0).Text)
}
