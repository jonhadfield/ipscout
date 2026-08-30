package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/datadog"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchDatadog(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Datadog", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Datadog", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "datadog", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run datadog")

	res, err := processor.Run(datadog.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Datadog", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "datadog", ip)}
	}

	slog.Debug("fetched data from Datadog", "ip", ip)

	var datadogResult datadog.HostSearchResult
	if err := json.Unmarshal([]byte(res), &datadogResult); err != nil {
		slog.Error("Failed to parse Datadog JSON", "error", err)

		return providerResult{text: simplifyError(err, "datadog", ip)}
	}

	table := createDatadogTable(ip, &datadogResult, false)

	return providerResult{table: table}
}

func createDatadogTable(ip string, result *datadog.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Datadog | Host: " + ip
	if isActive {
		headerText = " ▶ Datadog | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Datadog ranges").
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
