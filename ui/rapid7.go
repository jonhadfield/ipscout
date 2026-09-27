package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/rapid7"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchRapid7(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Rapid7", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Rapid7", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, rapid7.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run rapid7")

	res, err := processor.Run(rapid7.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Rapid7", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, rapid7.ProviderName, ip)}
	}

	slog.Debug("fetched data from Rapid7", "ip", ip)

	var result rapid7.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse Rapid7 JSON", "error", err)

		return providerResult{text: simplifyError(err, rapid7.ProviderName, ip)}
	}

	table := createRapid7Table(ip, &result, false)

	return providerResult{table: table}
}

func createRapid7Table(ip string, result *rapid7.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Rapid7 | Host: " + ip
	if isActive {
		headerText = " ▶ Rapid7 | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Rapid7 ranges").
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
