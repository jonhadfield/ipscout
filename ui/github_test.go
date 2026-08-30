package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/github"
	"github.com/stretchr/testify/require"
)

func TestCreateGitHubTable(t *testing.T) {
	t.Run("populated result", func(t *testing.T) {
		result := &github.HostSearchResult{
			Prefix:   netip.MustParsePrefix("192.30.252.0/22"),
			Services: []string{"api", "web"},
		}

		table := createGitHubTable("192.30.253.10", result, false)
		require.NotNil(t, table)
		require.Equal(t, " GitHub | Host: 192.30.253.10", table.GetCell(0, 0).Text)
		require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
		require.Equal(t, "192.30.252.0/22", table.GetCell(1, 1).Text)
		require.Equal(t, " Services", table.GetCell(2, 0).Text)
		require.Equal(t, "api, web", table.GetCell(2, 1).Text)
	})

	t.Run("no match", func(t *testing.T) {
		result := &github.HostSearchResult{}

		table := createGitHubTable("8.8.8.8", result, false)
		require.NotNil(t, table)
		require.Equal(t, " GitHub | Host: 8.8.8.8", table.GetCell(0, 0).Text)
		require.Equal(t, " IP not found in GitHub ranges", table.GetCell(1, 0).Text)
	})
}
