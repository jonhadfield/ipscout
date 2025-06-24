package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/ovh"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchOVH(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from OVH", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for OVH", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "ovh", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run ovh")

	res, err := processor.Run(ovh.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from OVH", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "ovh", ip)}
	}

	slog.Info("Fetching data from OVH", "ip", ip)

	// Parse OVH JSON response
	var ovhResult ovh.HostSearchResult
	if err := json.Unmarshal([]byte(res), &ovhResult); err != nil {
		slog.Error("Failed to parse OVH JSON", "error", err)

		return providerResult{text: simplifyError(err, "ovh", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createOVHTable(ip, &ovhResult, false)

	return providerResult{table: table}
}

func createOVHTable(ip string, result *ovh.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " OVH | Host: " + ip
	if isActive {
		headerText = " ▶ OVH | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have a valid prefix
	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No OVH prefix found").
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
	table.SetCell(row, 1, tview.NewTableCell("OVH Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
