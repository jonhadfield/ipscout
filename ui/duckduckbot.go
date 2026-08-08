package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/duckduckbot"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchDuckDuckBot(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from DuckDuckBot", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for DuckDuckBot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, duckduckbot.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run duckduckbot")

	res, err := processor.Run(duckduckbot.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from DuckDuckBot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, duckduckbot.ProviderName, ip)}
	}

	slog.Debug("fetched data from DuckDuckBot", "ip", ip)

	var duckduckbotResult duckduckbot.HostSearchResult
	if err := json.Unmarshal([]byte(res), &duckduckbotResult); err != nil {
		slog.Error("Failed to parse DuckDuckBot JSON", "error", err)

		return providerResult{text: simplifyError(err, duckduckbot.ProviderName, ip)}
	}

	table := createDuckDuckBotTable(ip, &duckduckbotResult, false)

	return providerResult{table: table}
}

func createDuckDuckBotTable(ip string, result *duckduckbot.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " DuckDuckBot | Host: " + ip
	if isActive {
		headerText = " ▶ DuckDuckBot | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No DuckDuckBot prefix found").
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
