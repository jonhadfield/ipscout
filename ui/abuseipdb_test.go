package ui

import (
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/abuseipdb"
)

func TestCreateAbuseIPDBTable(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		result *abuseipdb.HostSearchResult
	}{
		{
			name: "Clean IP",
			ip:   "8.8.8.8",
			result: &abuseipdb.HostSearchResult{
				Data: struct {
					IPAddress            string    `json:"ipAddress,omitempty"`
					IsPublic             bool      `json:"isPublic,omitempty"`
					IPVersion            int       `json:"ipVersion,omitempty"`
					IsWhitelisted        bool      `json:"isWhitelisted,omitempty"`
					AbuseConfidenceScore float64   `json:"abuseConfidenceScore,omitempty"`
					CountryCode          string    `json:"countryCode,omitempty"`
					CountryName          string    `json:"countryName,omitempty"`
					UsageType            string    `json:"usageType,omitempty"`
					Isp                  string    `json:"isp,omitempty"`
					Domain               string    `json:"domain,omitempty"`
					Hostnames            []string  `json:"hostnames,omitempty"`
					IsTor                bool      `json:"isTor,omitempty"`
					TotalReports         int       `json:"totalReports,omitempty"`
					NumDistinctUsers     int       `json:"numDistinctUsers,omitempty"`
					LastReportedAt       time.Time `json:"lastReportedAt,omitempty"`
					Reports              []struct {
						ReportedAt          time.Time `json:"reportedAt,omitempty"`
						Comment             string    `json:"comment,omitempty"`
						Categories          []int     `json:"categories,omitempty"`
						ReporterID          int       `json:"reporterId,omitempty"`
						ReporterCountryCode string    `json:"reporterCountryCode,omitempty"`
						ReporterCountryName string    `json:"reporterCountryName,omitempty"`
					} `json:"reports,omitempty"`
				}{
					IPAddress:            "8.8.8.8",
					AbuseConfidenceScore: 0,
					CountryCode:          "US",
					CountryName:          "United States",
					UsageType:            "Data Center/Web Hosting/Transit",
					Isp:                  "Google LLC",
					IsWhitelisted:        true,
					TotalReports:         0,
				},
			},
		},
		{
			name: "Malicious IP",
			ip:   "1.2.3.4",
			result: &abuseipdb.HostSearchResult{
				Data: struct {
					IPAddress            string    `json:"ipAddress,omitempty"`
					IsPublic             bool      `json:"isPublic,omitempty"`
					IPVersion            int       `json:"ipVersion,omitempty"`
					IsWhitelisted        bool      `json:"isWhitelisted,omitempty"`
					AbuseConfidenceScore float64   `json:"abuseConfidenceScore,omitempty"`
					CountryCode          string    `json:"countryCode,omitempty"`
					CountryName          string    `json:"countryName,omitempty"`
					UsageType            string    `json:"usageType,omitempty"`
					Isp                  string    `json:"isp,omitempty"`
					Domain               string    `json:"domain,omitempty"`
					Hostnames            []string  `json:"hostnames,omitempty"`
					IsTor                bool      `json:"isTor,omitempty"`
					TotalReports         int       `json:"totalReports,omitempty"`
					NumDistinctUsers     int       `json:"numDistinctUsers,omitempty"`
					LastReportedAt       time.Time `json:"lastReportedAt,omitempty"`
					Reports              []struct {
						ReportedAt          time.Time `json:"reportedAt,omitempty"`
						Comment             string    `json:"comment,omitempty"`
						Categories          []int     `json:"categories,omitempty"`
						ReporterID          int       `json:"reporterId,omitempty"`
						ReporterCountryCode string    `json:"reporterCountryCode,omitempty"`
						ReporterCountryName string    `json:"reporterCountryName,omitempty"`
					} `json:"reports,omitempty"`
				}{
					IPAddress:            "1.2.3.4",
					AbuseConfidenceScore: 85,
					CountryCode:          "CN",
					CountryName:          "China",
					UsageType:            "Data Center/Web Hosting/Transit",
					Isp:                  "Example ISP",
					TotalReports:         15,
					NumDistinctUsers:     8,
					LastReportedAt:       time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := createAbuseIPDBTable(tt.ip, tt.result, false)
			if table == nil {
				t.Error("createAbuseIPDBTable() returned nil table")

				return
			}

			// Basic checks
			if table.GetRowCount() == 0 {
				t.Error("createAbuseIPDBTable() returned table with no rows")
			}

			// Check that header is present
			cell := table.GetCell(0, 0)
			if cell == nil {
				t.Error("createAbuseIPDBTable() returned table with no header cell")

				return
			}

			headerText := cell.Text
			expectedHeader := " ABUSEIPDB | Host: " + tt.ip

			if headerText != expectedHeader {
				t.Errorf("createAbuseIPDBTable() header = %q, want %q", headerText, expectedHeader)
			}
		})
	}
}

func TestCreateAbuseIPDBTableActiveState(t *testing.T) {
	result := &abuseipdb.HostSearchResult{
		Data: struct {
			IPAddress            string    `json:"ipAddress,omitempty"`
			IsPublic             bool      `json:"isPublic,omitempty"`
			IPVersion            int       `json:"ipVersion,omitempty"`
			IsWhitelisted        bool      `json:"isWhitelisted,omitempty"`
			AbuseConfidenceScore float64   `json:"abuseConfidenceScore,omitempty"`
			CountryCode          string    `json:"countryCode,omitempty"`
			CountryName          string    `json:"countryName,omitempty"`
			UsageType            string    `json:"usageType,omitempty"`
			Isp                  string    `json:"isp,omitempty"`
			Domain               string    `json:"domain,omitempty"`
			Hostnames            []string  `json:"hostnames,omitempty"`
			IsTor                bool      `json:"isTor,omitempty"`
			TotalReports         int       `json:"totalReports,omitempty"`
			NumDistinctUsers     int       `json:"numDistinctUsers,omitempty"`
			LastReportedAt       time.Time `json:"lastReportedAt,omitempty"`
			Reports              []struct {
				ReportedAt          time.Time `json:"reportedAt,omitempty"`
				Comment             string    `json:"comment,omitempty"`
				Categories          []int     `json:"categories,omitempty"`
				ReporterID          int       `json:"reporterId,omitempty"`
				ReporterCountryCode string    `json:"reporterCountryCode,omitempty"`
				ReporterCountryName string    `json:"reporterCountryName,omitempty"`
			} `json:"reports,omitempty"`
		}{
			IPAddress:            "8.8.8.8",
			AbuseConfidenceScore: 50,
		},
	}
	ip := "8.8.8.8"

	// Test inactive state
	inactiveTable := createAbuseIPDBTable(ip, result, false)
	if inactiveTable == nil {
		t.Error("createAbuseIPDBTable() returned nil table for inactive state")

		return
	}

	inactiveCell := inactiveTable.GetCell(0, 0)
	if inactiveCell == nil {
		t.Error("createAbuseIPDBTable() returned table with no header cell for inactive state")

		return
	}

	expectedInactive := " ABUSEIPDB | Host: " + ip
	if inactiveCell.Text != expectedInactive {
		t.Errorf("createAbuseIPDBTable() inactive header = %q, want %q", inactiveCell.Text, expectedInactive)
	}

	// Test active state
	activeTable := createAbuseIPDBTable(ip, result, true)
	if activeTable == nil {
		t.Error("createAbuseIPDBTable() returned nil table for active state")

		return
	}

	activeCell := activeTable.GetCell(0, 0)
	if activeCell == nil {
		t.Error("createAbuseIPDBTable() returned table with no header cell for active state")

		return
	}

	expectedActive := " ▶ ABUSEIPDB | Host: " + ip
	if activeCell.Text != expectedActive {
		t.Errorf("createAbuseIPDBTable() active header = %q, want %q", activeCell.Text, expectedActive)
	}
}
