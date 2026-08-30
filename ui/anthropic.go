package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/anthropic"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchAnthropic(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Anthropic", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Anthropic", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, anthropic.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run anthropic")

	res, err := processor.Run(anthropic.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Anthropic", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, anthropic.ProviderName, ip)}
	}

	slog.Debug("fetched data from Anthropic", "ip", ip)

	var anthropicResult anthropic.HostSearchResult
	if err := json.Unmarshal([]byte(res), &anthropicResult); err != nil {
		slog.Error("Failed to parse Anthropic JSON", "error", err)

		return providerResult{text: simplifyError(err, anthropic.ProviderName, ip)}
	}

	table := createAnthropicTable(ip, &anthropicResult, false)

	return providerResult{table: table}
}

func createAnthropicTable(ip string, result *anthropic.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Anthropic | Host: " + ip
	if isActive {
		headerText = " ▶ Anthropic | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Anthropic prefix found").
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
