package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/sentry"
	"github.com/stretchr/testify/require"
)

const (
	testIPSentry     = "192.0.2.1"
	testPrefixSentry = "192.0.2.1/32"
	testHeaderSentry = " Sentry | Host: "
)

func TestCreateSentryTable(t *testing.T) {
	result := &sentry.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixSentry),
	}

	table := createSentryTable(testIPSentry, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderSentry+testIPSentry, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixSentry, table.GetCell(1, 1).Text)
}

func TestCreateSentryTableActive(t *testing.T) {
	result := &sentry.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixSentry),
	}

	table := createSentryTable(testIPSentry, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Sentry | Host: "+testIPSentry, table.GetCell(0, 0).Text)
}

func TestCreateSentryTableNoMatch(t *testing.T) {
	table := createSentryTable(testIPSentry, &sentry.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderSentry+testIPSentry, table.GetCell(0, 0).Text)
	require.Equal(t, " No Sentry prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestSentryActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createSentryTable(testIPSentry, &sentry.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixSentry),
	}, false)

	addActiveIndicatorToTable(table, providerSentry)

	require.Equal(t, " ▶ Sentry | Host: "+testIPSentry, table.GetCell(0, 0).Text)
}
