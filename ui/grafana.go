package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/grafana"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchGrafana(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Grafana", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Grafana", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, grafana.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run checkly")

	res, err := processor.Run(grafana.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Grafana", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, grafana.ProviderName, ip)}
	}

	slog.Debug("fetched data from Grafana", "ip", ip)

	var grafanaResult grafana.HostSearchResult
	if err := json.Unmarshal([]byte(res), &grafanaResult); err != nil {
		slog.Error("Failed to parse Grafana JSON", "error", err)

		return providerResult{text: simplifyError(err, grafana.ProviderName, ip)}
	}

	table := createGrafanaTable(ip, &grafanaResult, false)

	return providerResult{table: table}
}

func createGrafanaTable(ip string, result *grafana.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Grafana | Host: " + ip
	if isActive {
		headerText = " ▶ Grafana | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Grafana prefix found").
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
