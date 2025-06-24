package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/linode"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchLinode(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from Linode", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Linode", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "linode", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run linode")

	res, err := processor.Run(linode.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Linode", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "linode", ip)}
	}

	slog.Info("Fetching data from Linode", "ip", ip)

	// Parse Linode JSON response
	var linodeResult linode.HostSearchResult
	if err := json.Unmarshal([]byte(res), &linodeResult); err != nil {
		slog.Error("Failed to parse Linode JSON", "error", err)

		return providerResult{text: simplifyError(err, "linode", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createLinodeTable(ip, &linodeResult, false)

	return providerResult{table: table}
}

func createLinodeTable(ip string, result *linode.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " Linode | Host: " + ip
	if isActive {
		headerText = " ▶ Linode | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have a valid prefix
	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Linode prefix found").
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

	// Postal Code (commented out like in the original implementation)
	// if result.PostalCode != "" {
	//	table.SetCell(row, 0, tview.NewTableCell(" Postal Code").
	//		SetTextColor(tcell.ColorWhite).
	//		SetSelectable(false))
	//	table.SetCell(row, 1, tview.NewTableCell(result.PostalCode).
	//		SetTextColor(tcell.ColorWhite).
	//		SetSelectable(false))
	//
	//	row++
	// }

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
	table.SetCell(row, 1, tview.NewTableCell("Linode Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
