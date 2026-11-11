package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/googleuta"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchGoogleUTA(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Google User-triggered Agents", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Google User-triggered Agents", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, googleuta.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run googleuta")

	res, err := processor.Run(googleuta.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Google User-triggered Agents", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, googleuta.ProviderName, ip)}
	}

	slog.Debug("fetched data from Google User-triggered Agents", "ip", ip)

	var googleutaResult googleuta.HostSearchResult
	if err := json.Unmarshal([]byte(res), &googleutaResult); err != nil {
		slog.Error("Failed to parse Google User-triggered Agents JSON", "error", err)

		return providerResult{text: simplifyError(err, googleuta.ProviderName, ip)}
	}

	table := createGoogleUTATable(ip, &googleutaResult, false)

	return providerResult{table: table}
}

func createGoogleUTATable(ip string, result *googleuta.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Google User-triggered Agents | Host: " + ip
	if isActive {
		headerText = " ▶ Google User-triggered Agents | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Google User-triggered Agents prefix found").
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
