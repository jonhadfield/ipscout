package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/bunny"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchBunny(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Bunny CDN", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Bunny CDN", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "bunny", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run bunny")

	res, err := processor.Run(bunny.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Bunny CDN", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "bunny", ip)}
	}

	slog.Debug("fetched data from Bunny CDN", "ip", ip)

	var bunnyResult bunny.HostSearchResult
	if err := json.Unmarshal([]byte(res), &bunnyResult); err != nil {
		slog.Error("Failed to parse Bunny CDN JSON", "error", err)

		return providerResult{text: simplifyError(err, "bunny", ip)}
	}

	table := createBunnyTable(ip, &bunnyResult, false)

	return providerResult{table: table}
}

func createBunnyTable(ip string, result *bunny.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Bunny CDN | Host: " + ip
	if isActive {
		headerText = " ▶ Bunny CDN | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Bunny CDN ranges").
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
