package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/oci"
)

const testIPOCI = "192.0.2.1"

func TestCreateOCITable(t *testing.T) {
	result := &oci.HostSearchResult{
		Prefix: netip.MustParsePrefix("192.0.2.0/24"),
		Region: "us-ashburn-1",
		Tags:   []string{"OCI", "OBJECT_STORAGE"},
	}

	table := createOCITable(testIPOCI, result, false)
	if table == nil {
		t.Fatal("createOCITable() returned nil table")
	}

	if table.GetRowCount() == 0 {
		t.Fatal("createOCITable() returned table with no rows")
	}

	header := table.GetCell(0, 0)
	if header == nil {
		t.Fatal("createOCITable() returned table with no header cell")
	}

	expectedHeader := " Oracle Cloud (OCI) | Host: " + testIPOCI
	if header.Text != expectedHeader {
		t.Errorf("createOCITable() header = %q, want %q", header.Text, expectedHeader)
	}

	wantCells := []struct {
		row, col int
		text     string
	}{
		{1, 0, " Prefix"},
		{1, 1, "192.0.2.0/24"},
		{2, 0, " Region"},
		{2, 1, "us-ashburn-1"},
		{3, 0, " Tags"},
		{3, 1, "OCI, OBJECT_STORAGE"},
	}

	for _, want := range wantCells {
		cell := table.GetCell(want.row, want.col)
		if cell == nil {
			t.Errorf("createOCITable() missing cell at row %d col %d", want.row, want.col)

			continue
		}

		if cell.Text != want.text {
			t.Errorf("createOCITable() cell (%d,%d) = %q, want %q", want.row, want.col, cell.Text, want.text)
		}
	}
}

func TestCreateOCITableNoMatch(t *testing.T) {
	result := &oci.HostSearchResult{
		Prefix: netip.Prefix{}, // invalid prefix indicates no match
	}

	table := createOCITable(testIPExample, result, false)
	if table == nil {
		t.Fatal("createOCITable() returned nil table")
	}

	header := table.GetCell(0, 0)
	if header == nil {
		t.Fatal("createOCITable() returned table with no header cell")
	}

	expectedHeader := " Oracle Cloud (OCI) | Host: " + testIPExample
	if header.Text != expectedHeader {
		t.Errorf("createOCITable() header = %q, want %q", header.Text, expectedHeader)
	}

	cell := table.GetCell(1, 0)
	if cell == nil {
		t.Fatal("createOCITable() returned table with no message cell")
	}

	expectedMessage := " No matching Oracle Cloud (OCI) prefix"
	if cell.Text != expectedMessage {
		t.Errorf("createOCITable() no-match message = %q, want %q", cell.Text, expectedMessage)
	}
}

func TestCreateOCITableActiveState(t *testing.T) {
	result := &oci.HostSearchResult{
		Prefix: netip.MustParsePrefix("192.0.2.0/24"),
	}

	table := createOCITable(testIPOCI, result, true)
	if table == nil {
		t.Fatal("createOCITable() returned nil table for active state")
	}

	header := table.GetCell(0, 0)
	if header == nil {
		t.Fatal("createOCITable() returned table with no header cell for active state")
	}

	expectedHeader := " ▶ Oracle Cloud (OCI) | Host: " + testIPOCI
	if header.Text != expectedHeader {
		t.Errorf("createOCITable() active header = %q, want %q", header.Text, expectedHeader)
	}
}
