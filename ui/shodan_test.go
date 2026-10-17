package ui

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/shodan"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestCreateShodanTable(t *testing.T) {
	fixture := filepath.Join("..", "providers", "shodan", "testdata", "shodan_google_dns_resp.json")
	raw, err := os.ReadFile(fixture)
	require.NoError(t, err)

	var result shodan.HostSearchResult
	require.NoError(t, json.Unmarshal(raw, &result))

	table := createShodanTable(&result, false)
	require.NotNil(t, table)
	require.Greater(t, table.GetRowCount(), 0)

	active := createShodanTable(&result, true)
	require.NotNil(t, active)
	require.Contains(t, active.GetCell(0, 0).Text, "▶")
}

func TestCreateShodanTableMinimal(t *testing.T) {
	result := &shodan.HostSearchResult{
		IPStr:       testIPExample,
		Org:         "Example Org",
		Isp:         "Example ISP",
		Asn:         "AS64500",
		CountryName: "Canada",
		CountryCode: "CA",
		RegionCode:  "ON",
		City:        "Toronto",
		Latitude:    43.7,
		Longitude:   -79.4,
		LastUpdate:  "2024-01-02T03:04:05.000000",
		Ports:       []int{80, 443},
		Domains:     []string{"example.com"},
		Hostnames:   []string{"host.example.com"},
		Tags:        []any{"cloud", 42},
		Data: []shodan.HostSearchResultData{
			{
				Port:      443,
				Transport: "tcp",
				Org:       "Example Org",
				Domains:   []string{"example.com"},
				Timestamp: "2024-01-02T03:04:05.000000",
			},
		},
	}

	table := createShodanTable(result, false)
	require.NotNil(t, table)
	require.Greater(t, table.GetRowCount(), 5)
}

func TestFetchShodan(t *testing.T) {
	sess = session.New()
	sess.UseTestData = true
	sess.HTTPClient = helpers.GetHTTPClient()
	sess.Logger = slog.Default()
	sess.Providers.Shodan.Enabled = ToPtr(true)
	sess.Providers.Shodan.APIKey = "test-key"

	result := fetchShodan("8.8.8.8", sess)
	require.NotNil(t, result.table)
}
