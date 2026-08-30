package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/newrelic"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchNewRelic(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from New Relic", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for New Relic", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, newrelic.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run newrelic")

	res, err := processor.Run(newrelic.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from New Relic", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, newrelic.ProviderName, ip)}
	}

	slog.Debug("fetched data from New Relic", "ip", ip)

	var newrelicResult newrelic.HostSearchResult
	if err := json.Unmarshal([]byte(res), &newrelicResult); err != nil {
		slog.Error("Failed to parse New Relic JSON", "error", err)

		return providerResult{text: simplifyError(err, newrelic.ProviderName, ip)}
	}

	table := createNewRelicTable(ip, &newrelicResult, false)

	return providerResult{table: table}
}

func createNewRelicTable(ip string, result *newrelic.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " New Relic | Host: " + ip
	if isActive {
		headerText = " ▶ New Relic | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No New Relic prefix found").
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

	if result.Location != "" {
		row++

		table.SetCell(row, 0, tview.NewTableCell(" Location").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Location).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))
	}

	return table
}
