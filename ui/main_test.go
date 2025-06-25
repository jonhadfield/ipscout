package ui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func TestIsNoDataResult(t *testing.T) {
	tests := []struct {
		name     string
		result   providerResult
		expected bool
	}{
		{
			name: "Text result with no data",
			result: providerResult{
				text: "No data found",
			},
			expected: true,
		},
		{
			name: "Provider-prefixed no data result",
			result: providerResult{
				text: "annotated: No data found",
			},
			expected: true,
		},
		{
			name: "Text result with data",
			result: providerResult{
				text: "Some actual data here",
			},
			expected: false,
		},
		{
			name: "AWS table with no data message",
			result: providerResult{
				table: createTestAWSTableWithNoData(),
			},
			expected: true,
		},
		{
			name: "AWS table with actual data",
			result: providerResult{
				table: createTestAWSTableWithData(),
			},
			expected: false,
		},
		{
			name: "VirusTotal table with data",
			result: providerResult{
				table: createTestVirusTotalTable(),
			},
			expected: false,
		},
		{
			name: "AbuseIPDB table with data",
			result: providerResult{
				table: createTestAbuseIPDBTable(),
			},
			expected: false,
		},
		{
			name: "IPAPI table with data",
			result: providerResult{
				table: createTestIPAPITable(),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNoDataResult(tt.result)
			if result != tt.expected {
				t.Errorf("isNoDataResult() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func createTestAWSTableWithNoData() *tview.Table {
	table := tview.NewTable()
	table.SetCell(0, 0, tview.NewTableCell(" AWS | Host: 8.8.8.8").SetTextColor(tcell.ColorWhite))
	table.SetCell(1, 0, tview.NewTableCell(" No AWS prefix found").SetTextColor(tcell.ColorYellow))

	return table
}

func createTestAWSTableWithData() *tview.Table {
	table := tview.NewTable()
	table.SetCell(0, 0, tview.NewTableCell(" AWS | Host: 3.5.140.1").SetTextColor(tcell.ColorWhite))
	table.SetCell(1, 0, tview.NewTableCell("Region").SetTextColor(tcell.ColorWhite))
	table.SetCell(1, 1, tview.NewTableCell("us-east-1").SetTextColor(tcell.ColorLightCyan))

	return table
}

func createTestVirusTotalTable() *tview.Table {
	table := tview.NewTable()
	table.SetCell(0, 0, tview.NewTableCell(" VIRUSTOTAL | Host: 8.8.8.8").SetTextColor(tcell.ColorWhite))
	table.SetCell(1, 0, tview.NewTableCell("Detection Results").SetTextColor(tcell.ColorWhite))
	table.SetCell(2, 0, tview.NewTableCell("  - Harmless").SetTextColor(tcell.ColorWhite))
	table.SetCell(2, 1, tview.NewTableCell("85").SetTextColor(tcell.ColorGreen))

	return table
}

func createTestAbuseIPDBTable() *tview.Table {
	table := tview.NewTable()
	table.SetCell(0, 0, tview.NewTableCell(" ABUSEIPDB | Host: 8.8.8.8").SetTextColor(tcell.ColorWhite))
	table.SetCell(1, 0, tview.NewTableCell("Abuse Score").SetTextColor(tcell.ColorWhite))
	table.SetCell(1, 1, tview.NewTableCell("0%").SetTextColor(tcell.ColorGreen))

	return table
}

func createTestIPAPITable() *tview.Table {
	table := tview.NewTable()
	table.SetCell(0, 0, tview.NewTableCell(" IPAPI | Host: 8.8.8.8").SetTextColor(tcell.ColorWhite))
	table.SetCell(1, 0, tview.NewTableCell("Location").SetTextColor(tcell.ColorWhite))
	table.SetCell(2, 0, tview.NewTableCell("  - Country").SetTextColor(tcell.ColorWhite))
	table.SetCell(2, 1, tview.NewTableCell("United States (US)").SetTextColor(tcell.ColorWhite))

	return table
}
