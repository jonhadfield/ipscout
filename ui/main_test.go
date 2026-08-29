package ui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/providers/m247"
	"github.com/jonhadfield/ipscout/providers/openai"
	"github.com/jonhadfield/ipscout/providers/ovh"
	"github.com/jonhadfield/ipscout/providers/shodan"
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
				text: ErrMsgNoDataFound,
			},
			expected: true,
		},
		{
			name: "Provider-prefixed no data result",
			result: providerResult{
				text: "annotated: " + ErrMsgNoDataFound,
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

// addActiveIndicatorToTable marks the focused panel by rewriting its header. It
// has an explicit case per provider whose header differs from the upper-cased
// provider name, and falls back to replacing " "+strings.ToUpper(providerName)
// for the rest. These five rely on that fallback, so they are the ones a header
// rename would silently break: the replace finds nothing to match and the panel
// loses its marker with no error. Pin the headers that make the fallback work,
// built through the real table constructors rather than hand written.
func TestAddActiveIndicatorToTableFallback(t *testing.T) {
	const ip = "1.2.3.4"

	tests := []struct {
		provider string
		header   string
		newTable func() *tview.Table
	}{
		{
			provider: providerPTR,
			header:   " PTR | Host: " + ip,
			newTable: func() *tview.Table { return createPTRTable(ip, nil, false) },
		},
		{
			provider: providerShodan,
			header:   " SHODAN | Host: " + ip,
			newTable: func() *tview.Table {
				return createShodanTable(&shodan.HostSearchResult{IPStr: ip}, false)
			},
		},
		{
			provider: providerOpenAI,
			header:   " OPENAI | Host: " + ip,
			newTable: func() *tview.Table {
				return createOpenAITable(ip, &openai.HostSearchResult{}, false)
			},
		},
		{
			provider: providerOVH,
			header:   " OVH | Host: " + ip,
			newTable: func() *tview.Table { return createOVHTable(ip, &ovh.HostSearchResult{}, false) },
		},
		{
			provider: providerM247,
			header:   " M247 | Host: " + ip,
			newTable: func() *tview.Table { return createM247Table(ip, &m247.HostSearchResult{}, false) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			table := tt.newTable()

			cell := table.GetCell(0, 0)
			if cell.Text != tt.header {
				t.Fatalf("header = %q, want %q; the fallback only matches an upper-cased provider name", cell.Text, tt.header)
			}

			want := " \u25b6" + tt.header

			addActiveIndicatorToTable(table, tt.provider)

			if cell.Text != want {
				t.Errorf("header after = %q, want %q", cell.Text, want)
			}

			// A second call must not stack a second marker.
			addActiveIndicatorToTable(table, tt.provider)

			if cell.Text != want {
				t.Errorf("header after second add = %q, want %q", cell.Text, want)
			}
		})
	}
}
