package ui

import (
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/github"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchGitHub(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from GitHub", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for GitHub", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "github", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run github")

	res, err := processor.Run(github.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from GitHub", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "github", ip)}
	}

	slog.Debug("fetched data from GitHub", "ip", ip)

	var githubResult github.HostSearchResult
	if err := json.Unmarshal([]byte(res), &githubResult); err != nil {
		slog.Error("Failed to parse GitHub JSON", "error", err)

		return providerResult{text: simplifyError(err, "github", ip)}
	}

	table := createGitHubTable(ip, &githubResult, false)

	return providerResult{table: table}
}

func createGitHubTable(ip string, result *github.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " GitHub | Host: " + ip
	if isActive {
		headerText = " ▶ GitHub | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not found in GitHub ranges").
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

	row++

	if len(result.Services) > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Services").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(strings.Join(result.Services, ", ")).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
	}

	return table
}
