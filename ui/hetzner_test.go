package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/hetzner"
)

func TestCreateHetznerTable(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		result *hetzner.HostSearchResult
	}{
		{
			name: "Empty result",
			ip:   "1.2.3.4",
			result: &hetzner.HostSearchResult{
				Prefix: netip.Prefix{}, // Invalid prefix
			},
		},
		{
			name: "Valid hetzner result",
			ip:   "5.9.10.123",
			result: &hetzner.HostSearchResult{
				Prefix:       netip.MustParsePrefix("5.9.0.0/16"),
				CreationTime: time.Date(2024, 4, 30, 22, 0, 38, 0, time.UTC),
			},
		},
		{
			name: "Valid result without creation time",
			ip:   "5.9.10.100",
			result: &hetzner.HostSearchResult{
				Prefix: netip.MustParsePrefix("5.9.0.0/16"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := createHetznerTable(tt.ip, tt.result, false)
			if table == nil {
				t.Error("createHetznerTable() returned nil table")

				return
			}

			// Basic checks
			if table.GetRowCount() == 0 {
				t.Error("createHetznerTable() returned table with no rows")
			}

			// Check that header is present
			cell := table.GetCell(0, 0)
			if cell == nil {
				t.Error("createHetznerTable() returned table with no header cell")

				return
			}

			headerText := cell.Text
			expectedHeader := " HETZNER | Host: " + tt.ip

			if headerText != expectedHeader {
				t.Errorf("createHetznerTable() header = %q, want %q", headerText, expectedHeader)
			}
		})
	}
}

func TestCreateHetznerTableActiveState(t *testing.T) {
	result := &hetzner.HostSearchResult{
		Prefix: netip.MustParsePrefix("5.9.0.0/16"),
	}
	ip := "5.9.10.123"

	// Test inactive state
	inactiveTable := createHetznerTable(ip, result, false)
	if inactiveTable == nil {
		t.Error("createHetznerTable() returned nil table for inactive state")

		return
	}

	inactiveCell := inactiveTable.GetCell(0, 0)
	if inactiveCell == nil {
		t.Error("createHetznerTable() returned table with no header cell for inactive state")

		return
	}

	expectedInactive := " HETZNER | Host: " + ip
	if inactiveCell.Text != expectedInactive {
		t.Errorf("createHetznerTable() inactive header = %q, want %q", inactiveCell.Text, expectedInactive)
	}

	// Test active state
	activeTable := createHetznerTable(ip, result, true)
	if activeTable == nil {
		t.Error("createHetznerTable() returned nil table for active state")

		return
	}

	activeCell := activeTable.GetCell(0, 0)
	if activeCell == nil {
		t.Error("createHetznerTable() returned table with no header cell for active state")

		return
	}

	expectedActive := " ▶ HETZNER | Host: " + ip
	if activeCell.Text != expectedActive {
		t.Errorf("createHetznerTable() active header = %q, want %q", activeCell.Text, expectedActive)
	}
}

func TestAddActiveIndicatorToHetznerTable(t *testing.T) {
	result := &hetzner.HostSearchResult{
		Prefix: netip.MustParsePrefix("5.9.0.0/16"),
	}
	ip := "5.9.10.123"

	// Create table without arrow
	table := createHetznerTable(ip, result, false)
	if table == nil {
		t.Error("createHetznerTable() returned nil table")

		return
	}

	// Verify no arrow initially
	cell := table.GetCell(0, 0)
	if cell == nil {
		t.Error("table has no header cell")

		return
	}

	expectedBefore := " HETZNER | Host: " + ip
	if cell.Text != expectedBefore {
		t.Errorf("table header before = %q, want %q", cell.Text, expectedBefore)
	}

	// Add active indicator
	addActiveIndicatorToTable(table, "hetzner")

	// Verify arrow was added
	expectedAfter := " ▶ HETZNER | Host: " + ip

	if cell.Text != expectedAfter {
		t.Errorf("table header after = %q, want %q", cell.Text, expectedAfter)
	}

	// Test that adding indicator twice doesn't duplicate
	addActiveIndicatorToTable(table, "hetzner")

	if cell.Text != expectedAfter {
		t.Errorf("table header after double add = %q, want %q", cell.Text, expectedAfter)
	}
}
