package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/stopforumspam"
	"github.com/stretchr/testify/require"
)

const (
	testIPStopForumSpam     = "192.0.2.1"
	testPrefixStopForumSpam = "192.0.2.0/24"
)

func TestCreateStopForumSpamTable(t *testing.T) {
	result := &stopforumspam.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixStopForumSpam),
	}

	table := createStopForumSpamTable(testIPStopForumSpam, result, false)
	require.NotNil(t, table)

	require.Equal(t, " StopForumSpam | Host: "+testIPStopForumSpam, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixStopForumSpam, table.GetCell(1, 1).Text)
}

func TestCreateStopForumSpamTableActiveState(t *testing.T) {
	result := &stopforumspam.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixStopForumSpam),
	}

	table := createStopForumSpamTable(testIPStopForumSpam, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ StopForumSpam | Host: "+testIPStopForumSpam, table.GetCell(0, 0).Text)
}

func TestCreateStopForumSpamTableNoMatch(t *testing.T) {
	table := createStopForumSpamTable(testIPExample, &stopforumspam.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " StopForumSpam | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in StopForumSpam ranges", table.GetCell(1, 0).Text)
}
