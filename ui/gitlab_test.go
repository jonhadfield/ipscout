package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/gitlab"
	"github.com/stretchr/testify/require"
)

const (
	testIPGitLab     = "192.0.2.1"
	testPrefixGitLab = "192.0.2.0/24"
)

func TestCreateGitLabTable(t *testing.T) {
	result := &gitlab.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixGitLab),
	}

	table := createGitLabTable(testIPGitLab, result, false)
	require.NotNil(t, table)

	require.Equal(t, " GitLab | Host: "+testIPGitLab, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixGitLab, table.GetCell(1, 1).Text)
}

func TestCreateGitLabTableActiveState(t *testing.T) {
	result := &gitlab.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixGitLab),
	}

	table := createGitLabTable(testIPGitLab, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ GitLab | Host: "+testIPGitLab, table.GetCell(0, 0).Text)
}

func TestCreateGitLabTableNoMatch(t *testing.T) {
	table := createGitLabTable(testIPExample, &gitlab.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " GitLab | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in GitLab ranges", table.GetCell(1, 0).Text)
}
