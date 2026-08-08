package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/applebot"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchApplebot(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Applebot", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Applebot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, applebot.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run applebot")

	res, err := processor.Run(applebot.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Applebot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, applebot.ProviderName, ip)}
	}

	slog.Debug("fetched data from Applebot", "ip", ip)

	var applebotResult applebot.HostSearchResult
	if err := json.Unmarshal([]byte(res), &applebotResult); err != nil {
		slog.Error("Failed to parse Applebot JSON", "error", err)

		return providerResult{text: simplifyError(err, applebot.ProviderName, ip)}
	}

	table := createApplebotTable(ip, &applebotResult, false)

	return providerResult{table: table}
}

func createApplebotTable(ip string, result *applebot.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Applebot | Host: " + ip
	if isActive {
		headerText = " ▶ Applebot | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Applebot prefix found").
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

	row++

	if !result.CreationTime.IsZero() {
		table.SetCell(row, 0, tview.NewTableCell(" Creation Time").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.CreationTime.String()).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
	}

	return table
}
