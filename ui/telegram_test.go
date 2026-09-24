package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/telegram"
	"github.com/stretchr/testify/require"
)

const (
	testIPTelegram     = "192.0.2.1"
	testPrefixTelegram = "192.0.2.0/24"
)

func TestCreateTelegramTable(t *testing.T) {
	result := &telegram.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixTelegram),
	}

	table := createTelegramTable(testIPTelegram, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Telegram | Host: "+testIPTelegram, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixTelegram, table.GetCell(1, 1).Text)
}

func TestCreateTelegramTableActiveState(t *testing.T) {
	result := &telegram.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixTelegram),
	}

	table := createTelegramTable(testIPTelegram, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Telegram | Host: "+testIPTelegram, table.GetCell(0, 0).Text)
}

func TestCreateTelegramTableNoMatch(t *testing.T) {
	table := createTelegramTable(testIPExample, &telegram.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Telegram | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Telegram ranges", table.GetCell(1, 0).Text)
}
