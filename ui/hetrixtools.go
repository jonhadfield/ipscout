package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/hetrixtools"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchHetrixTools(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from HetrixTools", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for HetrixTools", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, hetrixtools.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run hetrixtools")

	res, err := processor.Run(hetrixtools.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from HetrixTools", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, hetrixtools.ProviderName, ip)}
	}

	slog.Debug("fetched data from HetrixTools", "ip", ip)

	var result hetrixtools.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse HetrixTools JSON", "error", err)

		return providerResult{text: simplifyError(err, hetrixtools.ProviderName, ip)}
	}

	table := createHetrixToolsTable(ip, &result, false)

	return providerResult{table: table}
}

func createHetrixToolsTable(ip string, result *hetrixtools.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " HetrixTools | Host: " + ip
	if isActive {
		headerText = " ▶ HetrixTools | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in HetrixTools ranges").
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
