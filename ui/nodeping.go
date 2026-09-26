package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/nodeping"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchNodePing(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from NodePing", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for NodePing", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, nodeping.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run nodeping")

	res, err := processor.Run(nodeping.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from NodePing", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, nodeping.ProviderName, ip)}
	}

	slog.Debug("fetched data from NodePing", "ip", ip)

	var result nodeping.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse NodePing JSON", "error", err)

		return providerResult{text: simplifyError(err, nodeping.ProviderName, ip)}
	}

	table := createNodePingTable(ip, &result, false)

	return providerResult{table: table}
}

func createNodePingTable(ip string, result *nodeping.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " NodePing | Host: " + ip
	if isActive {
		headerText = " ▶ NodePing | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in NodePing ranges").
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
