package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/hetzner"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchHetzner(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from Hetzner", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Hetzner", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "hetzner", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run hetzner")

	res, err := processor.Run(hetzner.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Hetzner", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "hetzner", ip)}
	}

	slog.Info("Fetching data from Hetzner", "ip", ip)

	// Parse Hetzner JSON response
	var hetznerResult hetzner.HostSearchResult
	if err := json.Unmarshal([]byte(res), &hetznerResult); err != nil {
		slog.Error("Failed to parse Hetzner JSON", "error", err)

		return providerResult{text: simplifyError(err, "hetzner", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createHetznerTable(ip, &hetznerResult, false)

	return providerResult{table: table}
}

func createHetznerTable(ip string, result *hetzner.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " HETZNER | Host: " + ip
	if isActive {
		headerText = " ▶ HETZNER | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have any data
	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Hetzner prefix found").
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
	table.SetCell(row, 1, tview.NewTableCell("Hosted by Hetzner").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
