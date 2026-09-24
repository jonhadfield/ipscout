package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/surfshark"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchSurfshark(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Surfshark", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Surfshark", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, surfshark.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run surfshark")

	res, err := processor.Run(surfshark.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Surfshark", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, surfshark.ProviderName, ip)}
	}

	slog.Debug("fetched data from Surfshark", "ip", ip)

	var result surfshark.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse Surfshark JSON", "error", err)

		return providerResult{text: simplifyError(err, surfshark.ProviderName, ip)}
	}

	table := createSurfsharkTable(ip, &result, false)

	return providerResult{table: table}
}

func createSurfsharkTable(ip string, result *surfshark.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Surfshark | Host: " + ip
	if isActive {
		headerText = " ▶ Surfshark | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Surfshark ranges").
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
