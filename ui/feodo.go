package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/feodo"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchFeodo(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Feodo Tracker", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Feodo Tracker", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, feodo.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run checkly")

	res, err := processor.Run(feodo.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Feodo Tracker", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, feodo.ProviderName, ip)}
	}

	slog.Debug("fetched data from Feodo Tracker", "ip", ip)

	var feodoResult feodo.HostSearchResult
	if err := json.Unmarshal([]byte(res), &feodoResult); err != nil {
		slog.Error("Failed to parse Feodo Tracker JSON", "error", err)

		return providerResult{text: simplifyError(err, feodo.ProviderName, ip)}
	}

	table := createFeodoTable(ip, &feodoResult, false)

	return providerResult{table: table}
}

func createFeodoTable(ip string, result *feodo.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Feodo Tracker | Host: " + ip
	if isActive {
		headerText = " ▶ Feodo Tracker | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Feodo Tracker prefix found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	table.SetCell(row, 0, tview.NewTableCell(" Prefix").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell(result.Prefix.String()).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	return table
}
