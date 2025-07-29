package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/scaleway"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchScaleway(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from Scaleway", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Scaleway", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "scaleway", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run scaleway")

	res, err := processor.Run(scaleway.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Scaleway", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "scaleway", ip)}
	}

	slog.Info("Fetching data from Scaleway", "ip", ip)

	// Parse Scaleway JSON response
	var scalewayResult scaleway.HostSearchResult
	if err := json.Unmarshal([]byte(res), &scalewayResult); err != nil {
		slog.Error("Failed to parse Scaleway JSON", "error", err)

		return providerResult{text: simplifyError(err, "scaleway", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createScalewayTable(ip, &scalewayResult, false)

	return providerResult{table: table}
}

func createScalewayTable(ip string, result *scaleway.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " Scaleway | Host: " + ip
	if isActive {
		headerText = " ▶ Scaleway | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have a valid prefix
	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Scaleway prefix found").
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
	table.SetCell(row, 1, tview.NewTableCell("Scaleway Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
