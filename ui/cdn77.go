package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/cdn77"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchCDN77(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from CDN77", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for CDN77", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "cdn77", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run cdn77")

	res, err := processor.Run(cdn77.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from CDN77", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "cdn77", ip)}
	}

	slog.Debug("fetched data from CDN77", "ip", ip)

	var cdn77Result cdn77.HostSearchResult
	if err := json.Unmarshal([]byte(res), &cdn77Result); err != nil {
		slog.Error("Failed to parse CDN77 JSON", "error", err)

		return providerResult{text: simplifyError(err, "cdn77", ip)}
	}

	table := createCDN77Table(ip, &cdn77Result, false)

	return providerResult{table: table}
}

func createCDN77Table(ip string, result *cdn77.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " CDN77 | Host: " + ip
	if isActive {
		headerText = " ▶ CDN77 | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in CDN77 ranges").
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
