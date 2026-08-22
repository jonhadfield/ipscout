package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/blocklistde"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchBlocklistDE(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Blocklist.de", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Blocklist.de", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, blocklistde.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run blocklistde")

	res, err := processor.Run(blocklistde.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Blocklist.de", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, blocklistde.ProviderName, ip)}
	}

	slog.Debug("fetched data from Blocklist.de", "ip", ip)

	var blocklistdeResult blocklistde.HostSearchResult
	if err := json.Unmarshal([]byte(res), &blocklistdeResult); err != nil {
		slog.Error("Failed to parse Blocklist.de JSON", "error", err)

		return providerResult{text: simplifyError(err, blocklistde.ProviderName, ip)}
	}

	table := createBlocklistDETable(ip, &blocklistdeResult, false)

	return providerResult{table: table}
}

func createBlocklistDETable(ip string, result *blocklistde.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Blocklist.de | Host: " + ip
	if isActive {
		headerText = " ▶ Blocklist.de | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Blocklist.de prefix found").
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
