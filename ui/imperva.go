package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/imperva"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchImperva(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Imperva", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Imperva", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "imperva", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run imperva")

	res, err := processor.Run(imperva.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Imperva", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "imperva", ip)}
	}

	slog.Debug("fetched data from Imperva", "ip", ip)

	var impervaResult imperva.HostSearchResult
	if err := json.Unmarshal([]byte(res), &impervaResult); err != nil {
		slog.Error("Failed to parse Imperva JSON", "error", err)

		return providerResult{text: simplifyError(err, "imperva", ip)}
	}

	table := createImpervaTable(ip, &impervaResult, false)

	return providerResult{table: table}
}

func createImpervaTable(ip string, result *imperva.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Imperva | Host: " + ip
	if isActive {
		headerText = " ▶ Imperva | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Imperva ranges").
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
