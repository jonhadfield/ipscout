package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/updown"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchUpdown(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from updown.io", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for updown.io", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, updown.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run checkly")

	res, err := processor.Run(updown.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from updown.io", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, updown.ProviderName, ip)}
	}

	slog.Debug("fetched data from updown.io", "ip", ip)

	var updownResult updown.HostSearchResult
	if err := json.Unmarshal([]byte(res), &updownResult); err != nil {
		slog.Error("Failed to parse updown.io JSON", "error", err)

		return providerResult{text: simplifyError(err, updown.ProviderName, ip)}
	}

	table := createUpdownTable(ip, &updownResult, false)

	return providerResult{table: table}
}

func createUpdownTable(ip string, result *updown.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " updown.io | Host: " + ip
	if isActive {
		headerText = " ▶ updown.io | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No updown.io prefix found").
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
