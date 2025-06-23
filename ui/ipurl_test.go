package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/ipurl"
)

func TestCreateIPURLTable(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		result *ipurl.HostSearchResult
	}{
		{
			name: "Empty result",
			ip:   "1.2.3.4",
			result: func() *ipurl.HostSearchResult {
				r := make(ipurl.HostSearchResult)

				return &r
			}(),
		},
		{
			name: "Single prefix with URLs",
			ip:   "5.105.62.60",
			result: func() *ipurl.HostSearchResult {
				r := make(ipurl.HostSearchResult)
				prefix := netip.MustParsePrefix("5.105.62.0/24")
				r[prefix] = []string{
					"https://example.com/list1.txt",
					"https://example.com/list2.txt",
				}

				return &r
			}(),
		},
		{
			name: "Multiple prefixes",
			ip:   "192.168.1.1",
			result: func() *ipurl.HostSearchResult {
				r := make(ipurl.HostSearchResult)
				prefix1 := netip.MustParsePrefix("192.168.1.0/24")
				prefix2 := netip.MustParsePrefix("192.168.0.0/16")
				r[prefix1] = []string{"https://example.com/subnet.txt"}
				r[prefix2] = []string{
					"https://example.com/network.txt",
					"https://example.com/ranges.txt",
				}

				return &r
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := createIPURLTable(tt.ip, tt.result, false)
			if table == nil {
				t.Error("createIPURLTable() returned nil table")

				return
			}

			// Basic checks
			if table.GetRowCount() == 0 {
				t.Error("createIPURLTable() returned table with no rows")
			}

			// Check that header is present
			cell := table.GetCell(0, 0)
			if cell == nil {
				t.Error("createIPURLTable() returned table with no header cell")

				return
			}

			headerText := cell.Text
			expectedHeader := " IP URL | Host: " + tt.ip

			if headerText != expectedHeader {
				t.Errorf("createIPURLTable() header = %q, want %q", headerText, expectedHeader)
			}
		})
	}
}

func TestCreateIPURLTableActiveState(t *testing.T) {
	result := make(ipurl.HostSearchResult)
	ip := "1.2.3.4"

	// Test inactive state
	inactiveTable := createIPURLTable(ip, &result, false)
	if inactiveTable == nil {
		t.Error("createIPURLTable() returned nil table for inactive state")

		return
	}

	inactiveCell := inactiveTable.GetCell(0, 0)
	if inactiveCell == nil {
		t.Error("createIPURLTable() returned table with no header cell for inactive state")

		return
	}

	expectedInactive := " IP URL | Host: " + ip
	if inactiveCell.Text != expectedInactive {
		t.Errorf("createIPURLTable() inactive header = %q, want %q", inactiveCell.Text, expectedInactive)
	}

	// Test active state
	activeTable := createIPURLTable(ip, &result, true)
	if activeTable == nil {
		t.Error("createIPURLTable() returned nil table for active state")

		return
	}

	activeCell := activeTable.GetCell(0, 0)
	if activeCell == nil {
		t.Error("createIPURLTable() returned table with no header cell for active state")

		return
	}

	expectedActive := " ▶ IP URL | Host: " + ip
	if activeCell.Text != expectedActive {
		t.Errorf("createIPURLTable() active header = %q, want %q", activeCell.Text, expectedActive)
	}
}

func TestAddActiveIndicatorToTable(t *testing.T) {
	result := make(ipurl.HostSearchResult)
	ip := "1.2.3.4"

	// Create table without arrow
	table := createIPURLTable(ip, &result, false)
	if table == nil {
		t.Error("createIPURLTable() returned nil table")

		return
	}

	// Verify no arrow initially
	cell := table.GetCell(0, 0)
	if cell == nil {
		t.Error("table has no header cell")

		return
	}

	expectedBefore := " IP URL | Host: " + ip
	if cell.Text != expectedBefore {
		t.Errorf("table header before = %q, want %q", cell.Text, expectedBefore)
	}

	// Add active indicator
	addActiveIndicatorToTable(table, "ipurl")

	// Verify arrow was added
	expectedAfter := " ▶ IP URL | Host: " + ip

	if cell.Text != expectedAfter {
		t.Errorf("table header after = %q, want %q", cell.Text, expectedAfter)
	}

	// Test that adding indicator twice doesn't duplicate
	addActiveIndicatorToTable(table, "ipurl")

	if cell.Text != expectedAfter {
		t.Errorf("table header after double add = %q, want %q", cell.Text, expectedAfter)
	}
}
