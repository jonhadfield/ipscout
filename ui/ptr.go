package ui

import (
	"fmt"
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/providers/ptr"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchPTR(ip string, sess *session.Session) providerResult { //nolint:revive
	sess.Logger.Info("Fetching data from PTR", "ip", ip)

	fr, err := ptr.FetchResponse(nil, ip, nil)
	if err != nil {
		sess.Logger.Error("Error fetching PTR data", "ip", ip, "error", err)

		return providerResult{text: fmt.Sprintf("Error fetching PTR data for %s: %v", ip, err)}
	}

	var records []string

	for _, rr := range fr.RR {
		if rr.Ptr != "" {
			sess.Logger.Info("Found PTR record", "ip", ip, "ptr", rr.Ptr)
			records = append(records, rr.Ptr)
		}
	}

	// Create PTR table
	table := createPTRTable(ip, records)

	return providerResult{table: table}
}

func createPTRTable(ip string, records []string) *tview.Table { //nolint:dupl
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header
	table.SetCell(row, 0, tview.NewTableCell(" PTR | Host: "+ip).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Records
	if len(records) > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Records").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(len(records))).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		for _, record := range records {
			table.SetCell(row, 0, tview.NewTableCell("   - Hostname").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(record).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	} else {
		table.SetCell(row, 0, tview.NewTableCell(" No PTR records found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		row++ //nolint:ineffassign,wastedassign
	}

	return table
}
