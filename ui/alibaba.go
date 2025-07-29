package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/alibaba"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchAlibaba(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from Alibaba", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Alibaba", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "alibaba", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run alibaba")

	res, err := processor.Run(alibaba.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Alibaba", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "alibaba", ip)}
	}

	slog.Info("Fetching data from Alibaba", "ip", ip)

	// Parse Alibaba JSON response
	var alibabaResult alibaba.HostSearchResult
	if err := json.Unmarshal([]byte(res), &alibabaResult); err != nil {
		slog.Error("Failed to parse Alibaba JSON", "error", err)

		return providerResult{text: simplifyError(err, "alibaba", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createAlibabaTable(ip, &alibabaResult, false)

	return providerResult{table: table}
}

func createAlibabaTable(ip string, result *alibaba.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " Alibaba | Host: " + ip
	if isActive {
		headerText = " ▶ Alibaba | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have a valid prefix
	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Alibaba prefix found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	// Display prefix
	table.SetCell(row, 0, tview.NewTableCell(" Prefix").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell(result.Prefix.String()).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Status
	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("Alibaba Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
