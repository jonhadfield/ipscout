package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/tenable"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchTenable(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Tenable", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Tenable", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, tenable.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run checkly")

	res, err := processor.Run(tenable.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Tenable", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, tenable.ProviderName, ip)}
	}

	slog.Debug("fetched data from Tenable", "ip", ip)

	var tenableResult tenable.HostSearchResult
	if err := json.Unmarshal([]byte(res), &tenableResult); err != nil {
		slog.Error("Failed to parse Tenable JSON", "error", err)

		return providerResult{text: simplifyError(err, tenable.ProviderName, ip)}
	}

	table := createTenableTable(ip, &tenableResult, false)

	return providerResult{table: table}
}

func createTenableTable(ip string, result *tenable.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Tenable | Host: " + ip
	if isActive {
		headerText = " ▶ Tenable | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Tenable prefix found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	addRow := func(label, value string) {
		if value == "" {
			return
		}

		table.SetCell(row, 0, tview.NewTableCell(" "+label).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(value).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++
	}

	addRow("Prefix", result.Prefix.String())
	addRow("Region", result.Region)
	addRow("Service", result.Service)
	addRow("Sensor Group", result.SensorGroup)

	if result.FedRAMP {
		addRow("FedRAMP", "true")
	}

	addRow("Created", result.CreateDate)

	return table
}
