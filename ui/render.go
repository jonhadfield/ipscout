package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/render"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchRender(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Render", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Render", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "render", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run render")

	res, err := processor.Run(render.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Render", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "render", ip)}
	}

	slog.Debug("fetched data from Render", "ip", ip)

	var renderResult render.HostSearchResult
	if err := json.Unmarshal([]byte(res), &renderResult); err != nil {
		slog.Error("Failed to parse Render JSON", "error", err)

		return providerResult{text: simplifyError(err, "render", ip)}
	}

	table := createRenderTable(ip, &renderResult, false)

	return providerResult{table: table}
}

func createRenderTable(ip string, result *render.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Render | Host: " + ip
	if isActive {
		headerText = " ▶ Render | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Render ranges").
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
