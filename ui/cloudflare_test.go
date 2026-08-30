package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/cloudflare"
)

const (
	testIPCloudflare     = "104.16.132.229"
	testPrefixCloudflare = "104.16.0.0/13"
)

func TestCreateCloudflareTable(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		result *cloudflare.HostSearchResult
	}{
		{
			name: testCaseEmptyResult,
			ip:   testIPExample,
			result: &cloudflare.HostSearchResult{
				Prefix: netip.Prefix{}, // Invalid prefix
			},
		},
		{
			name: "Valid cloudflare result",
			ip:   testIPCloudflare,
			result: &cloudflare.HostSearchResult{
				Prefix: netip.MustParsePrefix(testPrefixCloudflare),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := createCloudflareTable(tt.ip, tt.result, false)
			if table == nil {
				t.Error("createCloudflareTable() returned nil table")

				return
			}

			// Basic checks
			if table.GetRowCount() == 0 {
				t.Error("createCloudflareTable() returned table with no rows")
			}

			// Check that header is present
			cell := table.GetCell(0, 0)
			if cell == nil {
				t.Error("createCloudflareTable() returned table with no header cell")

				return
			}

			headerText := cell.Text
			expectedHeader := " Cloudflare | Host: " + tt.ip

			if headerText != expectedHeader {
				t.Errorf("createCloudflareTable() header = %q, want %q", headerText, expectedHeader)
			}
		})
	}
}

func TestCreateCloudflareTablePopulatedCells(t *testing.T) {
	result := &cloudflare.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCloudflare),
	}

	table := createCloudflareTable(testIPCloudflare, result, false)
	if table == nil {
		t.Fatal("createCloudflareTable() returned nil table")
	}

	// Row 1: prefix label and value
	labelCell := table.GetCell(1, 0)
	if labelCell == nil || labelCell.Text != " Prefix" {
		t.Errorf("createCloudflareTable() prefix label = %v, want %q", labelCell, " Prefix")
	}

	valueCell := table.GetCell(1, 1)
	if valueCell == nil || valueCell.Text != testPrefixCloudflare {
		t.Errorf("createCloudflareTable() prefix value = %v, want %q", valueCell, testPrefixCloudflare)
	}

	// Row 2: status
	statusCell := table.GetCell(2, 1)
	if statusCell == nil || statusCell.Text != "Hosted by Cloudflare" {
		t.Errorf("createCloudflareTable() status = %v, want %q", statusCell, "Hosted by Cloudflare")
	}
}

func TestCreateCloudflareTableNoMatch(t *testing.T) {
	result := &cloudflare.HostSearchResult{
		Prefix: netip.Prefix{},
	}

	table := createCloudflareTable(testIPExample, result, false)
	if table == nil {
		t.Fatal("createCloudflareTable() returned nil table")
	}

	cell := table.GetCell(1, 0)
	if cell == nil || cell.Text != " No Cloudflare prefix found" {
		t.Errorf("createCloudflareTable() no-match cell = %v, want %q", cell, " No Cloudflare prefix found")
	}
}

func TestCreateCloudflareTableActiveState(t *testing.T) {
	result := &cloudflare.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixCloudflare),
	}

	activeTable := createCloudflareTable(testIPCloudflare, result, true)
	if activeTable == nil {
		t.Fatal("createCloudflareTable() returned nil table for active state")
	}

	activeCell := activeTable.GetCell(0, 0)
	if activeCell == nil {
		t.Fatal("createCloudflareTable() returned table with no header cell for active state")
	}

	expectedActive := " ▶ Cloudflare | Host: " + testIPCloudflare
	if activeCell.Text != expectedActive {
		t.Errorf("createCloudflareTable() active header = %q, want %q", activeCell.Text, expectedActive)
	}
}
