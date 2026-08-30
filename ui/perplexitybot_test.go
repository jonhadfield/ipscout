package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/perplexitybot"
	"github.com/stretchr/testify/require"
)

const (
	testIPPerplexityBot     = "18.97.9.100"
	testPrefixPerplexityBot = "18.97.9.96/29"
	testHeaderPerplexityBot = " PerplexityBot | Host: "
)

func TestCreatePerplexityBotTable(t *testing.T) {
	creationTime := time.Date(2025, 2, 7, 16, 56, 0, 0, time.UTC)

	result := &perplexitybot.HostSearchResult{
		Prefix:       netip.MustParsePrefix(testPrefixPerplexityBot),
		CreationTime: creationTime,
	}

	table := createPerplexityBotTable(testIPPerplexityBot, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderPerplexityBot+testIPPerplexityBot, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixPerplexityBot, table.GetCell(1, 1).Text)
	require.Equal(t, " Creation Time", table.GetCell(2, 0).Text)
	require.Equal(t, creationTime.String(), table.GetCell(2, 1).Text)
}

func TestCreatePerplexityBotTableNoMatch(t *testing.T) {
	table := createPerplexityBotTable(testIPPerplexityBot, &perplexitybot.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderPerplexityBot+testIPPerplexityBot, table.GetCell(0, 0).Text)
	require.Equal(t, " No PerplexityBot prefix found", table.GetCell(1, 0).Text)
}
