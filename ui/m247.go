package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/m247"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchM247(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from M247", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for M247", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "m247", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run m247")

	res, err := processor.Run(m247.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from M247", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "m247", ip)}
	}

	slog.Info("Fetching data from M247", "ip", ip)

	// Parse M247 JSON response
	var m247Result m247.HostSearchResult
	if err = json.Unmarshal([]byte(res), &m247Result); err != nil {
		slog.Error("Failed to parse M247 JSON", "error", err)

		return providerResult{text: simplifyError(err, "m247", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createM247Table(ip, &m247Result, false)

	return providerResult{table: table}
}

func createM247Table(ip string, result *m247.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " M247 | Host: " + ip
	if isActive {
		headerText = " ▶ M247 | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have a valid prefix
	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No M247 prefix found").
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

	// Status
	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("M247 Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
