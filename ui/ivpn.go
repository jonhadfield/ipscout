package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/ivpn"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchIVPN(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from IVPN", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for IVPN", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, ivpn.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run ivpn")

	res, err := processor.Run(ivpn.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from IVPN", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, ivpn.ProviderName, ip)}
	}

	slog.Debug("fetched data from IVPN", "ip", ip)

	var result ivpn.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse IVPN JSON", "error", err)

		return providerResult{text: simplifyError(err, ivpn.ProviderName, ip)}
	}

	table := createIVPNTable(ip, &result, false)

	return providerResult{table: table}
}

func createIVPNTable(ip string, result *ivpn.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " IVPN | Host: " + ip
	if isActive {
		headerText = " ▶ IVPN | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in IVPN ranges").
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
