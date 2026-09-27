package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/intruder"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchIntruder(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Intruder", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Intruder", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, intruder.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run intruder")

	res, err := processor.Run(intruder.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Intruder", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, intruder.ProviderName, ip)}
	}

	slog.Debug("fetched data from Intruder", "ip", ip)

	var result intruder.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse Intruder JSON", "error", err)

		return providerResult{text: simplifyError(err, intruder.ProviderName, ip)}
	}

	table := createIntruderTable(ip, &result, false)

	return providerResult{table: table}
}

func createIntruderTable(ip string, result *intruder.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Intruder | Host: " + ip
	if isActive {
		headerText = " ▶ Intruder | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Intruder ranges").
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
