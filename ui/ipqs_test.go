package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/providers/ipqs"
)

func TestCreateIPQSTable(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		result *ipqs.HostSearchResult
	}{
		{
			name: "Failed result",
			ip:   "1.2.3.4",
			result: func() *ipqs.HostSearchResult {
				r := &ipqs.HostSearchResult{}
				r.Success = false
				r.Message = "API limit exceeded"

				return r
			}(),
		},
		{
			name: "Valid IPQS result",
			ip:   "74.125.219.32",
			result: func() *ipqs.HostSearchResult {
				r := &ipqs.HostSearchResult{}
				r.Success = true
				r.FraudScore = 75
				r.CountryCode = "US"
				r.Region = "California"
				r.City = "Mountain View"
				r.Isp = "Google LLC"
				r.Asn = 15169
				r.Host = "rate-limited-proxy-74-125-219-32.google.com"
				r.Proxy = true
				r.Vpn = true
				r.IsCrawler = true
				r.Latitude = 37.39
				r.Longitude = -122.07

				return r
			}(),
		},
		{
			name: "Low risk result",
			ip:   "8.8.8.8",
			result: func() *ipqs.HostSearchResult {
				r := &ipqs.HostSearchResult{}
				r.Success = true
				r.FraudScore = 25
				r.CountryCode = "US"
				r.Isp = "Google LLC"
				r.Asn = 15169

				return r
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := createIPQSTable(tt.ip, tt.result, false)
			if table == nil {
				t.Error("createIPQSTable() returned nil table")

				return
			}

			// Basic checks
			if table.GetRowCount() == 0 {
				t.Error("createIPQSTable() returned table with no rows")
			}

			// Check that header is present
			cell := table.GetCell(0, 0)
			if cell == nil {
				t.Error("createIPQSTable() returned table with no header cell")

				return
			}

			headerText := cell.Text
			expectedHeader := " IPQS | Host: " + tt.ip

			if headerText != expectedHeader {
				t.Errorf("createIPQSTable() header = %q, want %q", headerText, expectedHeader)
			}
		})
	}
}

func TestCreateIPQSTableActiveState(t *testing.T) {
	result := &ipqs.HostSearchResult{}
	result.Success = true
	result.FraudScore = 50
	ip := "74.125.219.32"

	// Test inactive state
	inactiveTable := createIPQSTable(ip, result, false)
	if inactiveTable == nil {
		t.Error("createIPQSTable() returned nil table for inactive state")

		return
	}

	inactiveCell := inactiveTable.GetCell(0, 0)
	if inactiveCell == nil {
		t.Error("createIPQSTable() returned table with no header cell for inactive state")

		return
	}

	expectedInactive := " IPQS | Host: " + ip
	if inactiveCell.Text != expectedInactive {
		t.Errorf("createIPQSTable() inactive header = %q, want %q", inactiveCell.Text, expectedInactive)
	}

	// Test active state
	activeTable := createIPQSTable(ip, result, true)
	if activeTable == nil {
		t.Error("createIPQSTable() returned nil table for active state")

		return
	}

	activeCell := activeTable.GetCell(0, 0)
	if activeCell == nil {
		t.Error("createIPQSTable() returned table with no header cell for active state")

		return
	}

	expectedActive := " ▶ IPQS | Host: " + ip
	if activeCell.Text != expectedActive {
		t.Errorf("createIPQSTable() active header = %q, want %q", activeCell.Text, expectedActive)
	}
}

func TestAddActiveIndicatorToIPQSTable(t *testing.T) {
	result := &ipqs.HostSearchResult{}
	result.Success = true
	result.FraudScore = 30
	ip := "74.125.219.32"

	// Create table without arrow
	table := createIPQSTable(ip, result, false)
	if table == nil {
		t.Error("createIPQSTable() returned nil table")

		return
	}

	// Verify no arrow initially
	cell := table.GetCell(0, 0)
	if cell == nil {
		t.Error("table has no header cell")

		return
	}

	expectedBefore := " IPQS | Host: " + ip
	if cell.Text != expectedBefore {
		t.Errorf("table header before = %q, want %q", cell.Text, expectedBefore)
	}

	// Add active indicator
	addActiveIndicatorToTable(table, "ipqs")

	// Verify arrow was added
	expectedAfter := " ▶ IPQS | Host: " + ip

	if cell.Text != expectedAfter {
		t.Errorf("table header after = %q, want %q", cell.Text, expectedAfter)
	}

	// Test that adding indicator twice doesn't duplicate
	addActiveIndicatorToTable(table, "ipqs")

	if cell.Text != expectedAfter {
		t.Errorf("table header after double add = %q, want %q", cell.Text, expectedAfter)
	}
}
