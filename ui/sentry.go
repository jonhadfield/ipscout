package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/sentry"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchSentry(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Sentry", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Sentry", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, sentry.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run checkly")

	res, err := processor.Run(sentry.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Sentry", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, sentry.ProviderName, ip)}
	}

	slog.Debug("fetched data from Sentry", "ip", ip)

	var sentryResult sentry.HostSearchResult
	if err := json.Unmarshal([]byte(res), &sentryResult); err != nil {
		slog.Error("Failed to parse Sentry JSON", "error", err)

		return providerResult{text: simplifyError(err, sentry.ProviderName, ip)}
	}

	table := createSentryTable(ip, &sentryResult, false)

	return providerResult{table: table}
}

func createSentryTable(ip string, result *sentry.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Sentry | Host: " + ip
	if isActive {
		headerText = " ▶ Sentry | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Sentry prefix found").
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
