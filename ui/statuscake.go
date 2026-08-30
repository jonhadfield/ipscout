package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/statuscake"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchStatusCake(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from StatusCake", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for StatusCake", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, statuscake.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run statuscake")

	res, err := processor.Run(statuscake.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from StatusCake", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, statuscake.ProviderName, ip)}
	}

	slog.Debug("fetched data from StatusCake", "ip", ip)

	var statuscakeResult statuscake.HostSearchResult
	if err := json.Unmarshal([]byte(res), &statuscakeResult); err != nil {
		slog.Error("Failed to parse StatusCake JSON", "error", err)

		return providerResult{text: simplifyError(err, statuscake.ProviderName, ip)}
	}

	table := createStatusCakeTable(ip, &statuscakeResult, false)

	return providerResult{table: table}
}

func createStatusCakeTable(ip string, result *statuscake.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " StatusCake | Host: " + ip
	if isActive {
		headerText = " ▶ StatusCake | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No StatusCake prefix found").
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

	if result.Location != "" {
		row++

		table.SetCell(row, 0, tview.NewTableCell(" Location").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Location).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))
	}

	if result.ServerCode != "" {
		row++

		table.SetCell(row, 0, tview.NewTableCell(" Server Code").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.ServerCode).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))
	}

	if result.Country != "" {
		row++

		table.SetCell(row, 0, tview.NewTableCell(" Country").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Country).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))
	}

	if result.Status != "" {
		row++

		table.SetCell(row, 0, tview.NewTableCell(" Status").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Status).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))
	}

	return table
}
