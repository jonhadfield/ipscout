package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/zoom"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchZoom(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Zoom", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Zoom", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, zoom.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run zoom")

	res, err := processor.Run(zoom.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Zoom", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, zoom.ProviderName, ip)}
	}

	slog.Debug("fetched data from Zoom", "ip", ip)

	var zoomResult zoom.HostSearchResult
	if err := json.Unmarshal([]byte(res), &zoomResult); err != nil {
		slog.Error("Failed to parse Zoom JSON", "error", err)

		return providerResult{text: simplifyError(err, zoom.ProviderName, ip)}
	}

	table := createZoomTable(ip, &zoomResult, false)

	return providerResult{table: table}
}

func createZoomTable(ip string, result *zoom.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Zoom | Host: " + ip
	if isActive {
		headerText = " ▶ Zoom | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Zoom prefix found").
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

	return table
}
