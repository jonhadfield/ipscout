package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/ccbot"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchCCBot(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from CCBot", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for CCBot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, ccbot.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run ccbot")

	res, err := processor.Run(ccbot.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from CCBot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, ccbot.ProviderName, ip)}
	}

	slog.Debug("fetched data from CCBot", "ip", ip)

	var ccbotResult ccbot.HostSearchResult
	if err := json.Unmarshal([]byte(res), &ccbotResult); err != nil {
		slog.Error("Failed to parse CCBot JSON", "error", err)

		return providerResult{text: simplifyError(err, ccbot.ProviderName, ip)}
	}

	table := createCCBotTable(ip, &ccbotResult, false)

	return providerResult{table: table}
}

func createCCBotTable(ip string, result *ccbot.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " CCBot | Host: " + ip
	if isActive {
		headerText = " ▶ CCBot | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No CCBot prefix found").
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
