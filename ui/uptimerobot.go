package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/uptimerobot"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchUptimeRobot(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from UptimeRobot", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for UptimeRobot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, uptimerobot.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run uptimerobot")

	res, err := processor.Run(uptimerobot.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from UptimeRobot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, uptimerobot.ProviderName, ip)}
	}

	slog.Debug("fetched data from UptimeRobot", "ip", ip)

	var uptimerobotResult uptimerobot.HostSearchResult
	if err := json.Unmarshal([]byte(res), &uptimerobotResult); err != nil {
		slog.Error("Failed to parse UptimeRobot JSON", "error", err)

		return providerResult{text: simplifyError(err, uptimerobot.ProviderName, ip)}
	}

	table := createUptimeRobotTable(ip, &uptimerobotResult, false)

	return providerResult{table: table}
}

func createUptimeRobotTable(ip string, result *uptimerobot.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " UptimeRobot | Host: " + ip
	if isActive {
		headerText = " ▶ UptimeRobot | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No UptimeRobot prefix found").
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
