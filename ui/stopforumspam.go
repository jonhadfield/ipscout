package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/stopforumspam"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchStopForumSpam(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from StopForumSpam", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for StopForumSpam", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, stopforumspam.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run stopforumspam")

	res, err := processor.Run(stopforumspam.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from StopForumSpam", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, stopforumspam.ProviderName, ip)}
	}

	slog.Debug("fetched data from StopForumSpam", "ip", ip)

	var result stopforumspam.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse StopForumSpam JSON", "error", err)

		return providerResult{text: simplifyError(err, stopforumspam.ProviderName, ip)}
	}

	table := createStopForumSpamTable(ip, &result, false)

	return providerResult{table: table}
}

func createStopForumSpamTable(ip string, result *stopforumspam.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " StopForumSpam | Host: " + ip
	if isActive {
		headerText = " ▶ StopForumSpam | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in StopForumSpam ranges").
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
