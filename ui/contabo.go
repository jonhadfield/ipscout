package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/contabo"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchContabo(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Contabo", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Contabo", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "contabo", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run contabo")

	res, err := processor.Run(contabo.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Contabo", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "contabo", ip)}
	}

	slog.Debug("fetched data from Contabo", "ip", ip)

	var contaboResult contabo.HostSearchResult
	if err := json.Unmarshal([]byte(res), &contaboResult); err != nil {
		slog.Error("Failed to parse Contabo JSON", "error", err)

		return providerResult{text: simplifyError(err, "contabo", ip)}
	}

	table := createContaboTable(ip, &contaboResult, false)

	return providerResult{table: table}
}

func createContaboTable(ip string, result *contabo.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Contabo | Host: " + ip
	if isActive {
		headerText = " ▶ Contabo | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Contabo ranges").
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
