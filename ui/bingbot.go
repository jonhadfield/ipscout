package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/bingbot"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchBingbot(ip string, sess *session.Session) providerResult { // nolint:dupl
	slog.Info("Fetching data from Bingbot", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Bingbot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "bingbot", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run bingbot")

	res, err := processor.Run(bingbot.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Bingbot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "bingbot", ip)}
	}

	slog.Info("Fetching data from Bingbot", "ip", ip)

	// Parse Bingbot JSON response
	var bingbotResult bingbot.HostSearchResult
	if err := json.Unmarshal([]byte(res), &bingbotResult); err != nil {
		slog.Error("Failed to parse Bingbot JSON", "error", err)

		return providerResult{text: simplifyError(err, "bingbot", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createBingbotTable(ip, &bingbotResult, false)

	return providerResult{table: table}
}

func createBingbotTable(ip string, result *bingbot.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " Bingbot | Host: " + ip
	if isActive {
		headerText = " ▶ Bingbot | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have a valid prefix
	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Bingbot prefix found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	// Display prefix
	table.SetCell(row, 0, tview.NewTableCell(" Prefix").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell(result.Prefix.String()).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Creation time if available
	if !result.CreationTime.IsZero() {
		table.SetCell(row, 0, tview.NewTableCell(" Creation Time").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.CreationTime.Format("2006-01-02 15:04:05")).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// Status
	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("Bingbot Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
