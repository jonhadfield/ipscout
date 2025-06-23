package ui

import (
	"encoding/json"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/annotated"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchAnnotated(ip string, sess *session.Session) providerResult { //nolint:revive
	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		sess.Logger.Error("Error parsing host for Annotated", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "annotated", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run annotated")

	res, err := processor.Run(annotated.ProviderName)
	if err != nil {
		sess.Logger.Error("Error fetching data from Annotated", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "annotated", ip)}
	}

	sess.Logger.Info("Fetching data from Annotated", "ip", ip)

	// Parse Annotated JSON response
	var annotatedResult annotated.HostSearchResult
	if err := json.Unmarshal([]byte(res), &annotatedResult); err != nil {
		sess.Logger.Error("Failed to parse Annotated JSON", "error", err)

		return providerResult{text: simplifyError(err, "annotated", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createAnnotatedTable(sess.Host.String(), &annotatedResult, false)

	return providerResult{table: table}
}

func createAnnotatedTable(ip string, result *annotated.HostSearchResult, isActive bool) *tview.Table { //nolint:dupl
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " Annotated | Host: " + ip
	if isActive {
		headerText = " ▶ Annotated | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Records
	if len(*result) > 0 {
		for p, annotations := range *result {
			table.SetCell(row, 0, tview.NewTableCell(" Prefix").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(p.String()).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++

			for _, annotation := range annotations {
				table.SetCell(row, 0, tview.NewTableCell("   - Annotations").
					SetTextColor(tcell.ColorWhite).
					SetSelectable(false))

				for _, note := range annotation.Notes {
					table.SetCell(row, 1, tview.NewTableCell(note).
						SetTextColor(tcell.ColorWhite).
						SetSelectable(false))

					row++
				}
				// table.SetCell(row, 1, tview.NewTableCell(annotation.Notes).
				// 	SetTextColor(tcell.ColorWhite).
				// 	SetSelectable(false))

				row++
			}
		}
	} else {
		table.SetCell(row, 0, tview.NewTableCell(" No Annotated records found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		row++ //nolint:ineffassign,wastedassign
	}

	return table
}
