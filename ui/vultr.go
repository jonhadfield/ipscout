package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/vultr"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchVultr(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from Vultr", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Vultr", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "vultr", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run vultr")

	res, err := processor.Run(vultr.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Vultr", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "vultr", ip)}
	}

	slog.Info("Fetching data from Vultr", "ip", ip)

	// Parse Vultr JSON response
	var vultrResult vultr.HostSearchResult
	if err := json.Unmarshal([]byte(res), &vultrResult); err != nil {
		slog.Error("Failed to parse Vultr JSON", "error", err)

		return providerResult{text: simplifyError(err, "vultr", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createVultrTable(ip, &vultrResult, false)

	return providerResult{table: table}
}

func createVultrTable(ip string, result *vultr.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " Vultr | Host: " + ip
	if isActive {
		headerText = " ▶ Vultr | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have a valid prefix
	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Vultr prefix found").
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
	table.SetCell(row, 1, tview.NewTableCell("Vultr Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
