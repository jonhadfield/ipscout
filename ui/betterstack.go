package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/betterstack"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchBetterStack(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Better Stack", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Better Stack", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, betterstack.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run betterstack")

	res, err := processor.Run(betterstack.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Better Stack", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, betterstack.ProviderName, ip)}
	}

	slog.Debug("fetched data from Better Stack", "ip", ip)

	var betterstackResult betterstack.HostSearchResult
	if err := json.Unmarshal([]byte(res), &betterstackResult); err != nil {
		slog.Error("Failed to parse Better Stack JSON", "error", err)

		return providerResult{text: simplifyError(err, betterstack.ProviderName, ip)}
	}

	table := createBetterStackTable(ip, &betterstackResult, false)

	return providerResult{table: table}
}

func createBetterStackTable(ip string, result *betterstack.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Better Stack | Host: " + ip
	if isActive {
		headerText = " ▶ Better Stack | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Better Stack prefix found").
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
