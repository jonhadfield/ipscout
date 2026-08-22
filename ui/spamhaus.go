package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/spamhaus"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchSpamhaus(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Spamhaus DROP", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Spamhaus DROP", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, spamhaus.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run spamhaus")

	res, err := processor.Run(spamhaus.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Spamhaus DROP", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, spamhaus.ProviderName, ip)}
	}

	slog.Debug("fetched data from Spamhaus DROP", "ip", ip)

	var spamhausResult spamhaus.HostSearchResult
	if err := json.Unmarshal([]byte(res), &spamhausResult); err != nil {
		slog.Error("Failed to parse Spamhaus DROP JSON", "error", err)

		return providerResult{text: simplifyError(err, spamhaus.ProviderName, ip)}
	}

	table := createSpamhausTable(ip, &spamhausResult, false)

	return providerResult{table: table}
}

func createSpamhausTable(ip string, result *spamhaus.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Spamhaus DROP | Host: " + ip
	if isActive {
		headerText = " ▶ Spamhaus DROP | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Spamhaus DROP listing found").
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

	if result.SBLID != "" {
		table.SetCell(row, 0, tview.NewTableCell(" SBL ID").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.SBLID).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.RIR != "" {
		table.SetCell(row, 0, tview.NewTableCell(" RIR").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.RIR).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if !result.Timestamp.IsZero() {
		table.SetCell(row, 0, tview.NewTableCell(" Timestamp").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Timestamp.String()).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
	}

	return table
}
