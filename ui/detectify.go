package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/detectify"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchDetectify(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Detectify", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Detectify", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, detectify.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run checkly")

	res, err := processor.Run(detectify.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Detectify", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, detectify.ProviderName, ip)}
	}

	slog.Debug("fetched data from Detectify", "ip", ip)

	var detectifyResult detectify.HostSearchResult
	if err := json.Unmarshal([]byte(res), &detectifyResult); err != nil {
		slog.Error("Failed to parse Detectify JSON", "error", err)

		return providerResult{text: simplifyError(err, detectify.ProviderName, ip)}
	}

	table := createDetectifyTable(ip, &detectifyResult, false)

	return providerResult{table: table}
}

func createDetectifyTable(ip string, result *detectify.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Detectify | Host: " + ip
	if isActive {
		headerText = " ▶ Detectify | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Detectify prefix found").
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
