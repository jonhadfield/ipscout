package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/binarydefense"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchBinaryDefense(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Binary Defense", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Binary Defense", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, binarydefense.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run binarydefense")

	res, err := processor.Run(binarydefense.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Binary Defense", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, binarydefense.ProviderName, ip)}
	}

	slog.Debug("fetched data from Binary Defense", "ip", ip)

	var result binarydefense.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse Binary Defense JSON", "error", err)

		return providerResult{text: simplifyError(err, binarydefense.ProviderName, ip)}
	}

	table := createBinaryDefenseTable(ip, &result, false)

	return providerResult{table: table}
}

func createBinaryDefenseTable(ip string, result *binarydefense.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Binary Defense | Host: " + ip
	if isActive {
		headerText = " ▶ Binary Defense | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Binary Defense ranges").
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
