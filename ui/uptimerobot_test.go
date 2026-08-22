package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/uptimerobot"
	"github.com/stretchr/testify/require"
)

const (
	testIPUptimeRobot     = "192.0.2.1"
	testPrefixUptimeRobot = "192.0.2.1/32"
	testHeaderUptimeRobot = " UptimeRobot | Host: "
)

func TestCreateUptimeRobotTable(t *testing.T) {
	result := &uptimerobot.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixUptimeRobot),
	}

	table := createUptimeRobotTable(testIPUptimeRobot, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderUptimeRobot+testIPUptimeRobot, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixUptimeRobot, table.GetCell(1, 1).Text)
}

func TestCreateUptimeRobotTableActive(t *testing.T) {
	result := &uptimerobot.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixUptimeRobot),
	}

	table := createUptimeRobotTable(testIPUptimeRobot, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ UptimeRobot | Host: "+testIPUptimeRobot, table.GetCell(0, 0).Text)
}

func TestCreateUptimeRobotTableNoMatch(t *testing.T) {
	table := createUptimeRobotTable(testIPUptimeRobot, &uptimerobot.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderUptimeRobot+testIPUptimeRobot, table.GetCell(0, 0).Text)
	require.Equal(t, " No UptimeRobot prefix found", table.GetCell(1, 0).Text)
}
