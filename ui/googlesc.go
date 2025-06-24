package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/googlesc"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchGoogleSC(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from Google Special Crawler", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Google Special Crawler", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "googlesc", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run googlesc")

	res, err := processor.Run(googlesc.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Google Special Crawler", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "googlesc", ip)}
	}

	slog.Info("Fetching data from Google Special Crawler", "ip", ip)

	// Parse Google Special Crawler JSON response
	var googlescResult googlesc.HostSearchResult
	if err := json.Unmarshal([]byte(res), &googlescResult); err != nil {
		slog.Error("Failed to parse Google Special Crawler JSON", "error", err)

		return providerResult{text: simplifyError(err, "googlesc", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createGoogleSCTable(ip, &googlescResult, false)

	return providerResult{table: table}
}

func createGoogleSCTable(ip string, result *googlesc.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " Google Special Crawler | Host: " + ip
	if isActive {
		headerText = " ▶ Google Special Crawler | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have a valid prefix
	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Google Special Crawler prefix found").
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
	table.SetCell(row, 1, tview.NewTableCell("Google Special Crawler Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
