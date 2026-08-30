package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/perplexitybot"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchPerplexityBot(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from PerplexityBot", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for PerplexityBot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, perplexitybot.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run perplexitybot")

	res, err := processor.Run(perplexitybot.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from PerplexityBot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, perplexitybot.ProviderName, ip)}
	}

	slog.Debug("fetched data from PerplexityBot", "ip", ip)

	var perplexitybotResult perplexitybot.HostSearchResult
	if err := json.Unmarshal([]byte(res), &perplexitybotResult); err != nil {
		slog.Error("Failed to parse PerplexityBot JSON", "error", err)

		return providerResult{text: simplifyError(err, perplexitybot.ProviderName, ip)}
	}

	table := createPerplexityBotTable(ip, &perplexitybotResult, false)

	return providerResult{table: table}
}

func createPerplexityBotTable(ip string, result *perplexitybot.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " PerplexityBot | Host: " + ip
	if isActive {
		headerText = " ▶ PerplexityBot | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No PerplexityBot prefix found").
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
