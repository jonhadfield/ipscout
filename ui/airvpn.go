package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/airvpn"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchAirVPN(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from AirVPN", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for AirVPN", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, airvpn.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run airvpn")

	res, err := processor.Run(airvpn.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from AirVPN", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, airvpn.ProviderName, ip)}
	}

	slog.Debug("fetched data from AirVPN", "ip", ip)

	var result airvpn.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse AirVPN JSON", "error", err)

		return providerResult{text: simplifyError(err, airvpn.ProviderName, ip)}
	}

	table := createAirVPNTable(ip, &result, false)

	return providerResult{table: table}
}

func createAirVPNTable(ip string, result *airvpn.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " AirVPN | Host: " + ip
	if isActive {
		headerText = " ▶ AirVPN | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in AirVPN ranges").
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
