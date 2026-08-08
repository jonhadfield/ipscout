package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/googleutf"
	"github.com/stretchr/testify/require"
)

const (
	testIPGoogleUTF     = "34.100.182.100"
	testPrefixGoogleUTF = "34.100.182.96/28"
	testHeaderGoogleUTF = " Google User-triggered Fetchers | Host: "
)

func TestCreateGoogleUTFTable(t *testing.T) {
	creationTime := time.Date(2024, 11, 14, 0, 0, 0, 0, time.UTC)

	result := &googleutf.HostSearchResult{
		Prefix:       netip.MustParsePrefix(testPrefixGoogleUTF),
		CreationTime: creationTime,
	}

	table := createGoogleUTFTable(testIPGoogleUTF, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderGoogleUTF+testIPGoogleUTF, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixGoogleUTF, table.GetCell(1, 1).Text)
	require.Equal(t, " Creation Time", table.GetCell(2, 0).Text)
	require.Equal(t, creationTime.String(), table.GetCell(2, 1).Text)
}

func TestCreateGoogleUTFTableNoMatch(t *testing.T) {
	table := createGoogleUTFTable(testIPGoogleUTF, &googleutf.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderGoogleUTF+testIPGoogleUTF, table.GetCell(0, 0).Text)
	require.Equal(t, " No Google User-triggered Fetchers prefix found", table.GetCell(1, 0).Text)
}
