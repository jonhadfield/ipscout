package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/googleutfg"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchGoogleUTFG(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Google User-triggered Fetchers (Google)", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Google User-triggered Fetchers (Google)", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, googleutfg.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run googleutfg")

	res, err := processor.Run(googleutfg.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Google User-triggered Fetchers (Google)", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, googleutfg.ProviderName, ip)}
	}

	slog.Debug("fetched data from Google User-triggered Fetchers (Google)", "ip", ip)

	var googleutfgResult googleutfg.HostSearchResult
	if err := json.Unmarshal([]byte(res), &googleutfgResult); err != nil {
		slog.Error("Failed to parse Google User-triggered Fetchers (Google) JSON", "error", err)

		return providerResult{text: simplifyError(err, googleutfg.ProviderName, ip)}
	}

	table := createGoogleUTFGTable(ip, &googleutfgResult, false)

	return providerResult{table: table}
}

func createGoogleUTFGTable(ip string, result *googleutfg.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Google User-triggered Fetchers (Google) | Host: " + ip
	if isActive {
		headerText = " ▶ Google User-triggered Fetchers (Google) | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Google User-triggered Fetchers (Google) prefix found").
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
