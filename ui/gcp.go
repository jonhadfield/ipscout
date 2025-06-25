package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/gcp"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchGCP(ip string, sess *session.Session) providerResult { // nolint:dupl
	slog.Info("Fetching data from GCP", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for GCP", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "gcp", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run gcp")

	res, err := processor.Run(gcp.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from GCP", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "gcp", ip)}
	}

	var gcpResult gcp.HostSearchResult
	if err := json.Unmarshal([]byte(res), &gcpResult); err != nil {
		slog.Error("Failed to parse GCP JSON", "error", err)

		return providerResult{text: simplifyError(err, "gcp", ip)}
	}

	table := createGCPTable(ip, &gcpResult, false)

	return providerResult{table: table}
}

func createGCPTable(ip string, result *gcp.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " GCP | Host: " + ip
	if isActive {
		headerText = " ▶ GCP | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" Prefix").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Prefix.String()).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++

		if result.Service != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Service").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Service).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Scope != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Scope").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Scope).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No GCP prefix found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("GCP Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
