package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/gcore"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchGcore(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Gcore", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Gcore", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, gcore.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run gcore")

	res, err := processor.Run(gcore.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Gcore", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, gcore.ProviderName, ip)}
	}

	slog.Debug("fetched data from Gcore", "ip", ip)

	var gcoreResult gcore.HostSearchResult
	if err := json.Unmarshal([]byte(res), &gcoreResult); err != nil {
		slog.Error("Failed to parse Gcore JSON", "error", err)

		return providerResult{text: simplifyError(err, gcore.ProviderName, ip)}
	}

	table := createGcoreTable(ip, &gcoreResult, false)

	return providerResult{table: table}
}

func createGcoreTable(ip string, result *gcore.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Gcore | Host: " + ip
	if isActive {
		headerText = " ▶ Gcore | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Gcore prefix found").
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
