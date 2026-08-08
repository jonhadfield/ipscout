package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/googleutf"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchGoogleUTF(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Google User-triggered Fetchers", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Google User-triggered Fetchers", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, googleutf.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run googleutf")

	res, err := processor.Run(googleutf.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Google User-triggered Fetchers", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, googleutf.ProviderName, ip)}
	}

	slog.Debug("fetched data from Google User-triggered Fetchers", "ip", ip)

	var googleutfResult googleutf.HostSearchResult
	if err := json.Unmarshal([]byte(res), &googleutfResult); err != nil {
		slog.Error("Failed to parse Google User-triggered Fetchers JSON", "error", err)

		return providerResult{text: simplifyError(err, googleutf.ProviderName, ip)}
	}

	table := createGoogleUTFTable(ip, &googleutfResult, false)

	return providerResult{table: table}
}

func createGoogleUTFTable(ip string, result *googleutf.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Google User-triggered Fetchers | Host: " + ip
	if isActive {
		headerText = " ▶ Google User-triggered Fetchers | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Google User-triggered Fetchers prefix found").
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

	if !result.CreationTime.IsZero() {
		table.SetCell(row, 0, tview.NewTableCell(" Creation Time").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.CreationTime.String()).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
	}

	return table
}
