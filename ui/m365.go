package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/m365"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchM365(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Microsoft 365", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Microsoft 365", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, m365.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run checkly")

	res, err := processor.Run(m365.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Microsoft 365", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, m365.ProviderName, ip)}
	}

	slog.Debug("fetched data from Microsoft 365", "ip", ip)

	var m365Result m365.HostSearchResult
	if err := json.Unmarshal([]byte(res), &m365Result); err != nil {
		slog.Error("Failed to parse Microsoft 365 JSON", "error", err)

		return providerResult{text: simplifyError(err, m365.ProviderName, ip)}
	}

	table := createM365Table(ip, &m365Result, false)

	return providerResult{table: table}
}

func createM365Table(ip string, result *m365.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Microsoft 365 | Host: " + ip
	if isActive {
		headerText = " ▶ Microsoft 365 | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Microsoft 365 prefix found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	addRow := func(label, value string) {
		if value == "" {
			return
		}

		table.SetCell(row, 0, tview.NewTableCell(" "+label).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(value).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++
	}

	addRow("Prefix", result.Prefix.String())
	addRow("Service Area", result.ServiceArea)
	addRow("Category", result.Category)

	return table
}
