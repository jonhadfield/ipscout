package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/grafana"
	"github.com/stretchr/testify/require"
)

const (
	testIPGrafana     = "192.0.2.1"
	testPrefixGrafana = "192.0.2.1/32"
	testHeaderGrafana = " Grafana | Host: "
)

func TestCreateGrafanaTable(t *testing.T) {
	result := &grafana.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixGrafana),
	}

	table := createGrafanaTable(testIPGrafana, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderGrafana+testIPGrafana, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixGrafana, table.GetCell(1, 1).Text)
}

func TestCreateGrafanaTableActive(t *testing.T) {
	result := &grafana.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixGrafana),
	}

	table := createGrafanaTable(testIPGrafana, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Grafana | Host: "+testIPGrafana, table.GetCell(0, 0).Text)
}

func TestCreateGrafanaTableNoMatch(t *testing.T) {
	table := createGrafanaTable(testIPGrafana, &grafana.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderGrafana+testIPGrafana, table.GetCell(0, 0).Text)
	require.Equal(t, " No Grafana prefix found", table.GetCell(1, 0).Text)
}

// addActiveIndicatorToTable falls back to upper-casing the provider name, which
// silently fails for a mixed case header. This is a separate path from the
// isActive rendering above, which builds its own header.
func TestGrafanaActiveIndicatorAddedToMixedCaseHeader(t *testing.T) {
	table := createGrafanaTable(testIPGrafana, &grafana.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixGrafana),
	}, false)

	addActiveIndicatorToTable(table, providerGrafana)

	require.Equal(t, " ▶ Grafana | Host: "+testIPGrafana, table.GetCell(0, 0).Text)
}
