package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/googlebot"
)

func TestCreateGooglebotTable(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		result *googlebot.HostSearchResult
	}{
		{
			name: "Empty result",
			ip:   "1.2.3.4",
			result: &googlebot.HostSearchResult{
				Prefix: netip.Prefix{}, // Invalid prefix
			},
		},
		{
			name: "Valid googlebot result",
			ip:   "66.249.77.135",
			result: &googlebot.HostSearchResult{
				Prefix:       netip.MustParsePrefix("66.249.77.128/27"),
				CreationTime: time.Date(2024, 4, 30, 22, 0, 38, 0, time.UTC),
			},
		},
		{
			name: "Valid result without creation time",
			ip:   "66.249.77.100",
			result: &googlebot.HostSearchResult{
				Prefix: netip.MustParsePrefix("66.249.77.128/27"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := createGooglebotTable(tt.ip, tt.result, false)
			if table == nil {
				t.Error("createGooglebotTable() returned nil table")

				return
			}

			// Basic checks
			if table.GetRowCount() == 0 {
				t.Error("createGooglebotTable() returned table with no rows")
			}

			// Check that header is present
			cell := table.GetCell(0, 0)
			if cell == nil {
				t.Error("createGooglebotTable() returned table with no header cell")

				return
			}

			headerText := cell.Text
			expectedHeader := " GOOGLEBOT | Host: " + tt.ip

			if headerText != expectedHeader {
				t.Errorf("createGooglebotTable() header = %q, want %q", headerText, expectedHeader)
			}
		})
	}
}

func TestCreateGooglebotTableActiveState(t *testing.T) {
	result := &googlebot.HostSearchResult{
		Prefix: netip.MustParsePrefix("66.249.77.128/27"),
	}
	ip := "66.249.77.135"

	// Test inactive state
	inactiveTable := createGooglebotTable(ip, result, false)
	if inactiveTable == nil {
		t.Error("createGooglebotTable() returned nil table for inactive state")

		return
	}

	inactiveCell := inactiveTable.GetCell(0, 0)
	if inactiveCell == nil {
		t.Error("createGooglebotTable() returned table with no header cell for inactive state")

		return
	}

	expectedInactive := " GOOGLEBOT | Host: " + ip
	if inactiveCell.Text != expectedInactive {
		t.Errorf("createGooglebotTable() inactive header = %q, want %q", inactiveCell.Text, expectedInactive)
	}

	// Test active state
	activeTable := createGooglebotTable(ip, result, true)
	if activeTable == nil {
		t.Error("createGooglebotTable() returned nil table for active state")

		return
	}

	activeCell := activeTable.GetCell(0, 0)
	if activeCell == nil {
		t.Error("createGooglebotTable() returned table with no header cell for active state")

		return
	}

	expectedActive := " ▶ GOOGLEBOT | Host: " + ip
	if activeCell.Text != expectedActive {
		t.Errorf("createGooglebotTable() active header = %q, want %q", activeCell.Text, expectedActive)
	}
}

func TestAddActiveIndicatorToGooglebotTable(t *testing.T) {
	result := &googlebot.HostSearchResult{
		Prefix: netip.MustParsePrefix("66.249.77.128/27"),
	}
	ip := "66.249.77.135"

	// Create table without arrow
	table := createGooglebotTable(ip, result, false)
	if table == nil {
		t.Error("createGooglebotTable() returned nil table")

		return
	}

	// Verify no arrow initially
	cell := table.GetCell(0, 0)
	if cell == nil {
		t.Error("table has no header cell")

		return
	}

	expectedBefore := " GOOGLEBOT | Host: " + ip
	if cell.Text != expectedBefore {
		t.Errorf("table header before = %q, want %q", cell.Text, expectedBefore)
	}

	// Add active indicator
	addActiveIndicatorToTable(table, "googlebot")

	// Verify arrow was added
	expectedAfter := " ▶ GOOGLEBOT | Host: " + ip

	if cell.Text != expectedAfter {
		t.Errorf("table header after = %q, want %q", cell.Text, expectedAfter)
	}

	// Test that adding indicator twice doesn't duplicate
	addActiveIndicatorToTable(table, "googlebot")

	if cell.Text != expectedAfter {
		t.Errorf("table header after double add = %q, want %q", cell.Text, expectedAfter)
	}
}
