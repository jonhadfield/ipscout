package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/uptrends"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchUptrends(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Uptrends", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Uptrends", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, uptrends.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run checkly")

	res, err := processor.Run(uptrends.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Uptrends", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, uptrends.ProviderName, ip)}
	}

	slog.Debug("fetched data from Uptrends", "ip", ip)

	var uptrendsResult uptrends.HostSearchResult
	if err := json.Unmarshal([]byte(res), &uptrendsResult); err != nil {
		slog.Error("Failed to parse Uptrends JSON", "error", err)

		return providerResult{text: simplifyError(err, uptrends.ProviderName, ip)}
	}

	table := createUptrendsTable(ip, &uptrendsResult, false)

	return providerResult{table: table}
}

func createUptrendsTable(ip string, result *uptrends.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Uptrends | Host: " + ip
	if isActive {
		headerText = " ▶ Uptrends | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Uptrends prefix found").
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
