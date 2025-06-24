package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/googlebot"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchGooglebot(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from Googlebot", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Googlebot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "googlebot", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run googlebot")

	res, err := processor.Run(googlebot.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Googlebot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "googlebot", ip)}
	}

	slog.Info("Fetching data from Googlebot", "ip", ip)

	// Parse Googlebot JSON response
	var googlebotResult googlebot.HostSearchResult
	if err := json.Unmarshal([]byte(res), &googlebotResult); err != nil {
		slog.Error("Failed to parse Googlebot JSON", "error", err)

		return providerResult{text: simplifyError(err, "googlebot", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createGooglebotTable(ip, &googlebotResult, false)

	return providerResult{table: table}
}

func createGooglebotTable(ip string, result *googlebot.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " GOOGLEBOT | Host: " + ip
	if isActive {
		headerText = " ▶ GOOGLEBOT | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have any data
	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Googlebot prefix found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	// Prefix information
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
		table.SetCell(row, 1, tview.NewTableCell(result.CreationTime.String()).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// Add a note about what this means
	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("Verified Googlebot IP").
		SetTextColor(tcell.ColorGreen).
		SetSelectable(false))

	return table
}
