package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/invicti"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchInvicti(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Invicti", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Invicti", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, invicti.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run invicti")

	res, err := processor.Run(invicti.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Invicti", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, invicti.ProviderName, ip)}
	}

	slog.Debug("fetched data from Invicti", "ip", ip)

	var result invicti.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse Invicti JSON", "error", err)

		return providerResult{text: simplifyError(err, invicti.ProviderName, ip)}
	}

	table := createInvictiTable(ip, &result, false)

	return providerResult{table: table}
}

func createInvictiTable(ip string, result *invicti.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Invicti | Host: " + ip
	if isActive {
		headerText = " ▶ Invicti | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Invicti ranges").
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
