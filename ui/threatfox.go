package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/threatfox"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchThreatFox(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from ThreatFox", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for ThreatFox", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, threatfox.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run threatfox")

	res, err := processor.Run(threatfox.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from ThreatFox", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, threatfox.ProviderName, ip)}
	}

	slog.Debug("fetched data from ThreatFox", "ip", ip)

	var result threatfox.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse ThreatFox JSON", "error", err)

		return providerResult{text: simplifyError(err, threatfox.ProviderName, ip)}
	}

	table := createThreatFoxTable(ip, &result, false)

	return providerResult{table: table}
}

func createThreatFoxTable(ip string, result *threatfox.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " ThreatFox | Host: " + ip
	if isActive {
		headerText = " ▶ ThreatFox | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in ThreatFox ranges").
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
