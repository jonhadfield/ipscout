package ui

import (
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/openai"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestCreateOpenAITable(t *testing.T) {
	fixture := filepath.Join("..", "providers", "openai", "testdata", "openai_20_171_206_1_report.json")
	raw, err := os.ReadFile(fixture)
	require.NoError(t, err)

	var result openai.HostSearchResult
	require.NoError(t, json.Unmarshal(raw, &result))

	table := createOpenAITable("20.171.206.1", &result, false)
	require.NotNil(t, table)
	require.Greater(t, table.GetRowCount(), 1)

	active := createOpenAITable("20.171.206.1", &result, true)
	require.Contains(t, active.GetCell(0, 0).Text, "▶")
}

func TestCreateOpenAITableNoMatch(t *testing.T) {
	table := createOpenAITable(testIPExample, &openai.HostSearchResult{}, false)
	require.NotNil(t, table)
	require.Contains(t, table.GetCell(1, 0).Text, "No OpenAI bot prefix found")
}

func TestCreateOpenAITableWithCreationTime(t *testing.T) {
	result := &openai.HostSearchResult{
		Matches: []openai.BotMatch{
			{
				Name:         "GPTBot",
				Prefix:       netip.MustParsePrefix("20.171.206.0/24"),
				CreationTime: time.Date(2025, 10, 30, 11, 0, 0, 0, time.UTC),
			},
		},
	}

	table := createOpenAITable("20.171.206.1", result, false)
	require.NotNil(t, table)
	require.Greater(t, table.GetRowCount(), 3)
}

func TestFetchOpenAI(t *testing.T) {
	sess = session.New()
	sess.UseTestData = true
	sess.HTTPClient = helpers.GetHTTPClient()
	sess.Logger = slog.Default()
	sess.Providers.OpenAI.Enabled = ToPtr(true)

	result := fetchOpenAI("20.171.206.1", sess)
	require.NotNil(t, result.table)
}
