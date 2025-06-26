package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/providers/virustotal"
)

func TestCreateVirusTotalTable(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		result *virustotal.HostSearchResult
	}{
		{
			name: "Clean result",
			ip:   "8.8.8.8",
			result: &virustotal.HostSearchResult{
				Data: virustotal.HostSearchResultData{
					Attributes: virustotal.HostSearchResultDataAttributes{
						LastAnalysisStats: virustotal.LastAnalysisStats{
							Harmless:   80,
							Malicious:  0,
							Suspicious: 0,
							Undetected: 5,
						},
						Country:   "US",
						Continent: "NA",
						Asn:       15169,
						AsOwner:   "Google LLC",
						Network:   "8.8.8.0/24",
					},
				},
			},
		},
		{
			name: "Malicious result",
			ip:   "1.2.3.4",
			result: &virustotal.HostSearchResult{
				Data: virustotal.HostSearchResultData{
					Attributes: virustotal.HostSearchResultDataAttributes{
						LastAnalysisStats: virustotal.LastAnalysisStats{
							Harmless:   5,
							Malicious:  10,
							Suspicious: 3,
							Undetected: 2,
						},
						Country:    "CN",
						Continent:  "AS",
						Asn:        4134,
						AsOwner:    "Example Corp",
						Reputation: -50,
					},
				},
			},
		},
		{
			name: "Error result",
			ip:   "invalid",
			result: &virustotal.HostSearchResult{
				Error: ErrMsgInvalidIPAddress,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := createVirusTotalTable(tt.ip, tt.result, false)
			if table == nil {
				t.Error("createVirusTotalTable() returned nil table")

				return
			}

			// Basic checks
			if table.GetRowCount() == 0 {
				t.Error("createVirusTotalTable() returned table with no rows")
			}

			// Check that header is present
			cell := table.GetCell(0, 0)
			if cell == nil {
				t.Error("createVirusTotalTable() returned table with no header cell")

				return
			}

			headerText := cell.Text
			expectedHeader := " VIRUSTOTAL | Host: " + tt.ip

			if headerText != expectedHeader {
				t.Errorf("createVirusTotalTable() header = %q, want %q", headerText, expectedHeader)
			}
		})
	}
}
