package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/googleutfg"
	"github.com/stretchr/testify/require"
)

const (
	testIPGoogleUTFG     = "142.250.32.1"
	testPrefixGoogleUTFG = "142.250.32.0/27"
	testHeaderGoogleUTFG = " Google User-triggered Fetchers (Google) | Host: "
)

func TestCreateGoogleUTFGTable(t *testing.T) {
	creation := time.Date(2026, 11, 11, 15, 46, 29, 0, time.UTC)

	result := &googleutfg.HostSearchResult{
		Prefix:       netip.MustParsePrefix(testPrefixGoogleUTFG),
		CreationTime: creation,
	}

	table := createGoogleUTFGTable(testIPGoogleUTFG, result, false)

	require.Equal(t, 3, table.GetRowCount())
	require.Equal(t, testHeaderGoogleUTFG+testIPGoogleUTFG, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixGoogleUTFG, table.GetCell(1, 1).Text)
	require.Equal(t, " Creation Time", table.GetCell(2, 0).Text)
}

func TestCreateGoogleUTFGTableNoMatch(t *testing.T) {
	table := createGoogleUTFGTable(testIPGoogleUTFG, &googleutfg.HostSearchResult{}, false)

	require.Equal(t, 2, table.GetRowCount())
	require.Equal(t, testHeaderGoogleUTFG+testIPGoogleUTFG, table.GetCell(0, 0).Text)
}
