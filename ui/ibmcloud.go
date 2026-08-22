package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/ibmcloud"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchIBMCloud(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from IBM Cloud", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for IBM Cloud", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "ibmcloud", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run ibmcloud")

	res, err := processor.Run(ibmcloud.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from IBM Cloud", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "ibmcloud", ip)}
	}

	slog.Debug("fetched data from IBM Cloud", "ip", ip)

	var ibmcloudResult ibmcloud.HostSearchResult
	if err := json.Unmarshal([]byte(res), &ibmcloudResult); err != nil {
		slog.Error("Failed to parse IBM Cloud JSON", "error", err)

		return providerResult{text: simplifyError(err, "ibmcloud", ip)}
	}

	table := createIBMCloudTable(ip, &ibmcloudResult, false)

	return providerResult{table: table}
}

func createIBMCloudTable(ip string, result *ibmcloud.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " IBM Cloud | Host: " + ip
	if isActive {
		headerText = " ▶ IBM Cloud | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in IBM Cloud ranges").
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
