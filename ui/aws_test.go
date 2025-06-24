package ui

import (
	"net/netip"
	"testing"
	"time"

	awsaws "github.com/jonhadfield/ip-fetcher/providers/aws"
	"github.com/jonhadfield/ipscout/providers/aws"
)

func TestCreateAWSTable(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		result *aws.HostSearchResult
	}{
		{
			name:   "No AWS prefix",
			ip:     "8.8.8.8",
			result: &aws.HostSearchResult{
				// Empty result
			},
		},
		{
			name: "Valid AWS IPv4 prefix",
			ip:   "3.5.140.1",
			result: &aws.HostSearchResult{
				Prefix: awsaws.Prefix{
					IPPrefix: netip.MustParsePrefix("3.5.140.0/22"),
					Region:   "us-east-1",
					Service:  "EC2",
				},
				CreateDate: time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "Valid AWS IPv6 prefix",
			ip:   "2600:1f13:e2f:1300::1",
			result: &aws.HostSearchResult{
				IPv6Prefix: awsaws.IPv6Prefix{
					IPv6Prefix: netip.MustParsePrefix("2600:1f13:e2f:1300::/56"),
					Region:     "us-west-2",
					Service:    "EC2",
				},
				CreateDate: time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := createAWSTable(tt.ip, tt.result, false)
			if table == nil {
				t.Error("createAWSTable() returned nil table")

				return
			}

			// Basic checks
			if table.GetRowCount() == 0 {
				t.Error("createAWSTable() returned table with no rows")
			}

			// Check that header is present
			cell := table.GetCell(0, 0)
			if cell == nil {
				t.Error("createAWSTable() returned table with no header cell")

				return
			}

			headerText := cell.Text
			expectedHeader := " AWS | Host: " + tt.ip

			if headerText != expectedHeader {
				t.Errorf("createAWSTable() header = %q, want %q", headerText, expectedHeader)
			}
		})
	}
}
