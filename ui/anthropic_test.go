package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/anthropic"
	"github.com/stretchr/testify/require"
)

const (
	testIPAnthropic     = "216.73.216.10"
	testPrefixAnthropic = "216.73.216.0/22"
	testHeaderAnthropic = " Anthropic | Host: "
)

func TestCreateAnthropicTable(t *testing.T) {
	creationTime := time.Date(2025, 8, 5, 9, 12, 0, 0, time.UTC)

	result := &anthropic.HostSearchResult{
		Prefix:       netip.MustParsePrefix(testPrefixAnthropic),
		CreationTime: creationTime,
	}

	table := createAnthropicTable(testIPAnthropic, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderAnthropic+testIPAnthropic, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixAnthropic, table.GetCell(1, 1).Text)
	require.Equal(t, " Creation Time", table.GetCell(2, 0).Text)
	require.Equal(t, creationTime.String(), table.GetCell(2, 1).Text)
}

func TestCreateAnthropicTableActive(t *testing.T) {
	result := &anthropic.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixAnthropic),
	}

	table := createAnthropicTable(testIPAnthropic, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Anthropic | Host: "+testIPAnthropic, table.GetCell(0, 0).Text)
	require.Equal(t, testPrefixAnthropic, table.GetCell(1, 1).Text)
}

func TestCreateAnthropicTableNoMatch(t *testing.T) {
	table := createAnthropicTable(testIPAnthropic, &anthropic.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderAnthropic+testIPAnthropic, table.GetCell(0, 0).Text)
	require.Equal(t, " No Anthropic prefix found", table.GetCell(1, 0).Text)
}
