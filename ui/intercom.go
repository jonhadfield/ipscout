package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/intercom"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchIntercom(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Intercom", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Intercom", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, intercom.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run intercom")

	res, err := processor.Run(intercom.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Intercom", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, intercom.ProviderName, ip)}
	}

	slog.Debug("fetched data from Intercom", "ip", ip)

	var result intercom.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse Intercom JSON", "error", err)

		return providerResult{text: simplifyError(err, intercom.ProviderName, ip)}
	}

	table := createIntercomTable(ip, &result, false)

	return providerResult{table: table}
}

func createIntercomTable(ip string, result *intercom.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Intercom | Host: " + ip
	if isActive {
		headerText = " ▶ Intercom | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Intercom ranges").
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
	addRow("Region", result.Region)
	addRow("Service", result.Service)

	return table
}
