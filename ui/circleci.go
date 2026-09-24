package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/circleci"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchCircleCI(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from CircleCI", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for CircleCI", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, circleci.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run circleci")

	res, err := processor.Run(circleci.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from CircleCI", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, circleci.ProviderName, ip)}
	}

	slog.Debug("fetched data from CircleCI", "ip", ip)

	var result circleci.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse CircleCI JSON", "error", err)

		return providerResult{text: simplifyError(err, circleci.ProviderName, ip)}
	}

	table := createCircleCITable(ip, &result, false)

	return providerResult{table: table}
}

func createCircleCITable(ip string, result *circleci.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " CircleCI | Host: " + ip
	if isActive {
		headerText = " ▶ CircleCI | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in CircleCI ranges").
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
