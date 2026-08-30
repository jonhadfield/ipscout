package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/emergingthreats"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchEmergingThreats(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Emerging Threats", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Emerging Threats", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, emergingthreats.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run emergingthreats")

	res, err := processor.Run(emergingthreats.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Emerging Threats", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, emergingthreats.ProviderName, ip)}
	}

	slog.Debug("fetched data from Emerging Threats", "ip", ip)

	var emergingthreatsResult emergingthreats.HostSearchResult
	if err := json.Unmarshal([]byte(res), &emergingthreatsResult); err != nil {
		slog.Error("Failed to parse Emerging Threats JSON", "error", err)

		return providerResult{text: simplifyError(err, emergingthreats.ProviderName, ip)}
	}

	table := createEmergingThreatsTable(ip, &emergingthreatsResult, false)

	return providerResult{table: table}
}

func createEmergingThreatsTable(ip string, result *emergingthreats.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Emerging Threats | Host: " + ip
	if isActive {
		headerText = " ▶ Emerging Threats | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Emerging Threats prefix found").
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

	row++

	table.SetCell(row, 0, tview.NewTableCell(" List").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("compromised IPs").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))

	return table
}
