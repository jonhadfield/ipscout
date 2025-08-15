package ui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/providers/ptr"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchPTR(ip string, sess *session.Session) providerResult { //nolint:revive
	sess.Logger.Info("Fetching data from PTR", "ip", ip)

	fr, err := ptr.FetchResponse(sess.Logger, ip, nil)
	if err != nil {
		sess.Logger.Error("Error fetching PTR data", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "ptr", ip)}
	}

	// Pass the full DNS records to the table for detailed display
	table := createPTRTable(ip, fr.RR, false)

	return providerResult{table: table}
}

const (
	colPTR        = "PTR"
	colNAME       = "NAME"
	colTTL        = "TTL"
	colRDLEN      = "RDLEN"
	colCLASS      = "CLASS"
	colTYPE       = "TYPE"
	maxPTRLength  = 22
	maxNAMELength = 30
)

func createPTRTable(ip string, records []*ptr.Ptr, isActive bool) *tview.Table { //nolint:dupl
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " PTR | Host: " + ip
	if isActive {
		headerText = " ▶ PTR | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if len(records) > 0 { //nolint:nestif
		// Create formatted text display instead of multi-column table
		headerLine := fmt.Sprintf("%-22s %-30s %8s %6s %5s %4s", colPTR, colNAME, colTTL, colRDLEN, colCLASS, colTYPE)
		table.SetCell(row, 0, tview.NewTableCell(headerLine).
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		row++

		// Data rows as formatted text
		for _, record := range records {
			if record.Ptr != "" {
				// Truncate PTR value if too long
				ptrValue := record.Ptr
				if len(ptrValue) > maxPTRLength {
					ptrValue = ptrValue[:maxPTRLength-3] + "..."
				}

				// Truncate NAME value if too long
				nameValue := record.Header.Name
				if len(nameValue) > maxNAMELength {
					nameValue = nameValue[:maxNAMELength-3] + "..."
				}

				dataLine := fmt.Sprintf("%-22s %-30s %8d %6d %5d %4d",
					ptrValue,
					nameValue,
					record.Header.Ttl,
					record.Header.Rdlength,
					record.Header.Class,
					record.Header.Rrtype)

				table.SetCell(row, 0, tview.NewTableCell(dataLine).
					SetTextColor(tcell.ColorWhite).
					SetSelectable(false))

				row++
			}
		}
	} else {
		table.SetCell(row, 0, tview.NewTableCell(" No PTR records found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		row++ //nolint:ineffassign,wastedassign
	}

	return table
}
