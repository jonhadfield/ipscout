package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/zscaler"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchZscaler(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from Zscaler", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Zscaler", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "zscaler", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run zscaler")

	res, err := processor.Run(zscaler.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Zscaler", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "zscaler", ip)}
	}

	slog.Info("Fetching data from Zscaler", "ip", ip)

	// Parse Zscaler JSON response
	var zscalerResult zscaler.HostSearchResult
	if err := json.Unmarshal([]byte(res), &zscalerResult); err != nil {
		slog.Error("Failed to parse Zscaler JSON", "error", err)

		return providerResult{text: simplifyError(err, "zscaler", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createZscalerTable(ip, &zscalerResult, false)

	return providerResult{table: table}
}

func createZscalerTable(ip string, result *zscaler.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " Zscaler | Host: " + ip
	if isActive {
		headerText = " ▶ Zscaler | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have a range
	if result.Range == "" {
		table.SetCell(row, 0, tview.NewTableCell(" No Zscaler range found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	// Display range
	table.SetCell(row, 0, tview.NewTableCell(" Range").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell(result.Range).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Continent
	if result.Continent != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Continent").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Continent).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// City
	if result.City != "" {
		table.SetCell(row, 0, tview.NewTableCell(" City").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.City).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// Hostname
	if result.Hostname != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Hostname").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Hostname).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// GRE
	if result.GRE != "" {
		table.SetCell(row, 0, tview.NewTableCell(" GRE").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.GRE).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// VPN
	if result.VPN != "" {
		table.SetCell(row, 0, tview.NewTableCell(" VPN").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.VPN).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// Latitude
	if result.Latitude != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Latitude").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Latitude).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// Longitude
	if result.Longtitude != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Longitude").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Longtitude).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// Status
	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("Zscaler Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
