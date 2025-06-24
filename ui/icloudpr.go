package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/icloudpr"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchICloudPR(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from iCloud Private Relay", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for iCloud Private Relay", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "icloudpr", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run icloudpr")

	res, err := processor.Run(icloudpr.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from iCloud Private Relay", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "icloudpr", ip)}
	}

	slog.Info("Fetching data from iCloud Private Relay", "ip", ip)

	// Parse iCloud Private Relay JSON response
	var icloudprResult icloudpr.HostSearchResult
	if err := json.Unmarshal([]byte(res), &icloudprResult); err != nil {
		slog.Error("Failed to parse iCloud Private Relay JSON", "error", err)

		return providerResult{text: simplifyError(err, "icloudpr", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createICloudPRTable(ip, &icloudprResult, false)

	return providerResult{table: table}
}

func createICloudPRTable(ip string, result *icloudpr.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " iCloud Private Relay | Host: " + ip
	if isActive {
		headerText = " ▶ iCloud Private Relay | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have a valid prefix
	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No iCloud Private Relay prefix found").
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

	// Alpha2Code
	if result.Alpha2Code != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Country Code").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Alpha2Code).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// Region
	if result.Region != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Region").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Region).
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

	// Postal Code
	if result.PostalCode != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Postal Code").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.PostalCode).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// Sync Token
	if result.SyncToken != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Sync Token").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.SyncToken).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

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
	table.SetCell(row, 1, tview.NewTableCell("iCloud Private Relay Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
