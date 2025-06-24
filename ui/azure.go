package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/azure"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchAzure(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from Azure", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Azure", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "azure", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run azure")

	res, err := processor.Run(azure.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Azure", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "azure", ip)}
	}

	slog.Info("Fetching data from Azure", "ip", ip)

	var azureResult azure.HostSearchResult
	if err := json.Unmarshal([]byte(res), &azureResult); err != nil {
		slog.Error("Failed to parse Azure JSON", "error", err)

		return providerResult{text: simplifyError(err, "azure", ip)}
	}

	table := createAzureTable(ip, &azureResult, false)

	return providerResult{table: table}
}

func createAzureTable(ip string, result *azure.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Azure | Host: " + ip
	if isActive {
		headerText = " ▶ Azure | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if result.Name != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Name").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Name).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++
	}

	if result.ID != "" {
		table.SetCell(row, 0, tview.NewTableCell(" ID").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.ID).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" Prefix").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Prefix.String()).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++
	}

	if result.Properties.Region != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Region").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Properties.Region).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.Properties.Platform != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Platform").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Properties.Platform).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.Cloud != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Cloud").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Cloud).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.Properties.SystemService != "" {
		table.SetCell(row, 0, tview.NewTableCell(" System Service").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Properties.SystemService).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Azure prefix found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("Azure Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
