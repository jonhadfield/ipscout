package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/mullvad"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchMullvad(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Mullvad", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Mullvad", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, mullvad.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run mullvad")

	res, err := processor.Run(mullvad.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Mullvad", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, mullvad.ProviderName, ip)}
	}

	slog.Debug("fetched data from Mullvad", "ip", ip)

	var result mullvad.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse Mullvad JSON", "error", err)

		return providerResult{text: simplifyError(err, mullvad.ProviderName, ip)}
	}

	table := createMullvadTable(ip, &result, false)

	return providerResult{table: table}
}

func createMullvadTable(ip string, result *mullvad.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Mullvad | Host: " + ip
	if isActive {
		headerText = " ▶ Mullvad | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Mullvad ranges").
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
