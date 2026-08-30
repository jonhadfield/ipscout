package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/openai"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchOpenAI(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from OpenAI", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for OpenAI", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "openai", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run openai")

	res, err := processor.Run(openai.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from OpenAI", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "openai", ip)}
	}

	slog.Info("Fetching data from OpenAI", "ip", ip)

	// Parse OpenAI JSON response
	var openaiResult openai.HostSearchResult
	if err := json.Unmarshal([]byte(res), &openaiResult); err != nil {
		slog.Error("Failed to parse OpenAI JSON", "error", err)

		return providerResult{text: simplifyError(err, "openai", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createOpenAITable(ip, &openaiResult, false)

	return providerResult{table: table}
}

func createOpenAITable(ip string, result *openai.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " OPENAI | Host: " + ip
	if isActive {
		headerText = " ▶ OPENAI | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have any data
	if len(result.Matches) == 0 {
		table.SetCell(row, 0, tview.NewTableCell(" No OpenAI bot prefix found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	for _, match := range result.Matches {
		// Bot name
		table.SetCell(row, 0, tview.NewTableCell(" Bot").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(match.Name).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++

		// Prefix information
		table.SetCell(row, 0, tview.NewTableCell(" Prefix").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(match.Prefix.String()).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++

		// Creation time if available
		if !match.CreationTime.IsZero() {
			table.SetCell(row, 0, tview.NewTableCell(" Creation Time").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(match.CreationTime.String()).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	// Add a note about what this means
	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("Verified OpenAI bot IP").
		SetTextColor(tcell.ColorGreen).
		SetSelectable(false))

	return table
}
