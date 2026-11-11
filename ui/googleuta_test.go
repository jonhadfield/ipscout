package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/googleuta"
	"github.com/stretchr/testify/require"
)

const (
	testIPGoogleUTA     = "136.121.16.1"
	testPrefixGoogleUTA = "136.121.16.0/24"
	testHeaderGoogleUTA = " Google User-triggered Agents | Host: "
)

func TestCreateGoogleUTATable(t *testing.T) {
	creation := time.Date(2026, 11, 11, 15, 46, 12, 0, time.UTC)

	result := &googleuta.HostSearchResult{
		Prefix:       netip.MustParsePrefix(testPrefixGoogleUTA),
		CreationTime: creation,
	}

	table := createGoogleUTATable(testIPGoogleUTA, result, false)

	require.Equal(t, 3, table.GetRowCount())
	require.Equal(t, testHeaderGoogleUTA+testIPGoogleUTA, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixGoogleUTA, table.GetCell(1, 1).Text)
	require.Equal(t, " Creation Time", table.GetCell(2, 0).Text)
}

func TestCreateGoogleUTATableNoMatch(t *testing.T) {
	table := createGoogleUTATable(testIPGoogleUTA, &googleuta.HostSearchResult{}, false)

	require.Equal(t, 2, table.GetRowCount())
	require.Equal(t, testHeaderGoogleUTA+testIPGoogleUTA, table.GetCell(0, 0).Text)
}
