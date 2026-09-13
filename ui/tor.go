package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/tor"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchTor(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Tor Exit Node", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Tor Exit Node", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, tor.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run checkly")

	res, err := processor.Run(tor.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Tor Exit Node", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, tor.ProviderName, ip)}
	}

	slog.Debug("fetched data from Tor Exit Node", "ip", ip)

	var torResult tor.HostSearchResult
	if err := json.Unmarshal([]byte(res), &torResult); err != nil {
		slog.Error("Failed to parse Tor Exit Node JSON", "error", err)

		return providerResult{text: simplifyError(err, tor.ProviderName, ip)}
	}

	table := createTorTable(ip, &torResult, false)

	return providerResult{table: table}
}

func createTorTable(ip string, result *tor.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Tor Exit Node | Host: " + ip
	if isActive {
		headerText = " ▶ Tor Exit Node | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Tor Exit Node prefix found").
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
