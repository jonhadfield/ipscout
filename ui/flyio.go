package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/flyio"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchFlyio(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Fly.io", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Fly.io", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "flyio", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run flyio")

	res, err := processor.Run(flyio.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Fly.io", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "flyio", ip)}
	}

	slog.Debug("fetched data from Fly.io", "ip", ip)

	var flyioResult flyio.HostSearchResult
	if err := json.Unmarshal([]byte(res), &flyioResult); err != nil {
		slog.Error("Failed to parse Fly.io JSON", "error", err)

		return providerResult{text: simplifyError(err, "flyio", ip)}
	}

	table := createFlyioTable(ip, &flyioResult, false)

	return providerResult{table: table}
}

func createFlyioTable(ip string, result *flyio.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Fly.io | Host: " + ip
	if isActive {
		headerText = " ▶ Fly.io | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Fly.io ranges").
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
