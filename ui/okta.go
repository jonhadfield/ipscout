package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/okta"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchOkta(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Okta", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Okta", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, okta.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run checkly")

	res, err := processor.Run(okta.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Okta", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, okta.ProviderName, ip)}
	}

	slog.Debug("fetched data from Okta", "ip", ip)

	var oktaResult okta.HostSearchResult
	if err := json.Unmarshal([]byte(res), &oktaResult); err != nil {
		slog.Error("Failed to parse Okta JSON", "error", err)

		return providerResult{text: simplifyError(err, okta.ProviderName, ip)}
	}

	table := createOktaTable(ip, &oktaResult, false)

	return providerResult{table: table}
}

func createOktaTable(ip string, result *okta.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Okta | Host: " + ip
	if isActive {
		headerText = " ▶ Okta | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Okta prefix found").
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
	addRow("Cell", result.Cell)

	return table
}
