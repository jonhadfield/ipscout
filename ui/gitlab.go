package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/gitlab"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchGitLab(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from GitLab", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for GitLab", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, gitlab.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run gitlab")

	res, err := processor.Run(gitlab.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from GitLab", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, gitlab.ProviderName, ip)}
	}

	slog.Debug("fetched data from GitLab", "ip", ip)

	var result gitlab.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse GitLab JSON", "error", err)

		return providerResult{text: simplifyError(err, gitlab.ProviderName, ip)}
	}

	table := createGitLabTable(ip, &result, false)

	return providerResult{table: table}
}

func createGitLabTable(ip string, result *gitlab.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " GitLab | Host: " + ip
	if isActive {
		headerText = " ▶ GitLab | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in GitLab ranges").
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
