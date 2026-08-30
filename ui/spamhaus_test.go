package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/spamhaus"
	"github.com/stretchr/testify/require"
)

const (
	testIPSpamhaus           = "192.0.2.5"
	testPrefixSpamhaus       = "192.0.2.0/24"
	testSBLIDSpamhaus        = "SBL123456"
	testRIRSpamhaus          = "ripencc"
	testHeaderSpamhaus       = " Spamhaus DROP | Host: "
	testActiveHeaderSpamhaus = " ▶ Spamhaus DROP | Host: "
)

func TestCreateSpamhausTable(t *testing.T) {
	timestamp := time.Date(2025, 2, 7, 16, 56, 0, 0, time.UTC)

	result := &spamhaus.HostSearchResult{
		Prefix:    netip.MustParsePrefix(testPrefixSpamhaus),
		SBLID:     testSBLIDSpamhaus,
		RIR:       testRIRSpamhaus,
		Timestamp: timestamp,
	}

	table := createSpamhausTable(testIPSpamhaus, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderSpamhaus+testIPSpamhaus, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixSpamhaus, table.GetCell(1, 1).Text)
	require.Equal(t, " SBL ID", table.GetCell(2, 0).Text)
	require.Equal(t, testSBLIDSpamhaus, table.GetCell(2, 1).Text)
	require.Equal(t, " RIR", table.GetCell(3, 0).Text)
	require.Equal(t, testRIRSpamhaus, table.GetCell(3, 1).Text)
	require.Equal(t, " Timestamp", table.GetCell(4, 0).Text)
	require.Equal(t, timestamp.String(), table.GetCell(4, 1).Text)
}

func TestCreateSpamhausTableMinimalResult(t *testing.T) {
	result := &spamhaus.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixSpamhaus),
	}

	table := createSpamhausTable(testIPSpamhaus, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixSpamhaus, table.GetCell(1, 1).Text)
	require.Equal(t, 2, table.GetRowCount())
}

func TestCreateSpamhausTableNoMatch(t *testing.T) {
	table := createSpamhausTable(testIPSpamhaus, &spamhaus.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderSpamhaus+testIPSpamhaus, table.GetCell(0, 0).Text)
	require.Equal(t, " No Spamhaus DROP listing found", table.GetCell(1, 0).Text)
}

func TestCreateSpamhausTableActiveHeader(t *testing.T) {
	table := createSpamhausTable(testIPSpamhaus, &spamhaus.HostSearchResult{}, true)
	require.NotNil(t, table)

	require.Equal(t, testActiveHeaderSpamhaus+testIPSpamhaus, table.GetCell(0, 0).Text)
}
