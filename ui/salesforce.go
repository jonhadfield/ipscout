package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/salesforce"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchSalesforce(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Salesforce", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Salesforce", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, salesforce.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run salesforce")

	res, err := processor.Run(salesforce.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Salesforce", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, salesforce.ProviderName, ip)}
	}

	slog.Debug("fetched data from Salesforce", "ip", ip)

	var result salesforce.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse Salesforce JSON", "error", err)

		return providerResult{text: simplifyError(err, salesforce.ProviderName, ip)}
	}

	table := createSalesforceTable(ip, &result, false)

	return providerResult{table: table}
}

func createSalesforceTable(ip string, result *salesforce.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Salesforce | Host: " + ip
	if isActive {
		headerText = " ▶ Salesforce | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Salesforce ranges").
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
	addRow("Provider", result.Provider)

	return table
}
