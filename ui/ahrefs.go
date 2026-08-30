package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/ahrefs"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchAhrefs(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from AhrefsBot", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for AhrefsBot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, ahrefs.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run ahrefs")

	res, err := processor.Run(ahrefs.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from AhrefsBot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, ahrefs.ProviderName, ip)}
	}

	slog.Debug("fetched data from AhrefsBot", "ip", ip)

	var ahrefsResult ahrefs.HostSearchResult
	if err := json.Unmarshal([]byte(res), &ahrefsResult); err != nil {
		slog.Error("Failed to parse AhrefsBot JSON", "error", err)

		return providerResult{text: simplifyError(err, ahrefs.ProviderName, ip)}
	}

	table := createAhrefsTable(ip, &ahrefsResult, false)

	return providerResult{table: table}
}

func createAhrefsTable(ip string, result *ahrefs.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " AhrefsBot | Host: " + ip
	if isActive {
		headerText = " ▶ AhrefsBot | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No AhrefsBot prefix found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	table.SetCell(row, 0, tview.NewTableCell(" Prefix").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell(result.Prefix.String()).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.CreationTime.IsZero() {
		table.SetCell(row, 0, tview.NewTableCell(" Creation Time").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.CreationTime.String()).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
	}

	return table
}
