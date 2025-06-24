package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/aws"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchAWS(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from AWS", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for AWS", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "aws", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run aws")

	res, err := processor.Run(aws.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from AWS", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "aws", ip)}
	}

	slog.Info("Fetching data from AWS", "ip", ip)

	// Parse AWS JSON response
	var awsResult aws.HostSearchResult
	if err := json.Unmarshal([]byte(res), &awsResult); err != nil {
		slog.Error("Failed to parse AWS JSON", "error", err)

		return providerResult{text: simplifyError(err, "aws", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createAWSTable(ip, &awsResult, false)

	return providerResult{table: table}
}

func createAWSTable(ip string, result *aws.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " AWS | Host: " + ip
	if isActive {
		headerText = " ▶ AWS | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check IPv4 prefix
	if result.IPPrefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IPv4 Prefix").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.IPPrefix.String()).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++

		if result.Prefix.Region != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Region").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Prefix.Region).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Prefix.Service != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Service").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Prefix.Service).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	// Check IPv6 prefix
	if result.IPv6Prefix.IPv6Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IPv6 Prefix").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.IPv6Prefix.IPv6Prefix.String()).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++

		if result.IPv6Prefix.Region != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Region").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.IPv6Prefix.Region).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.IPv6Prefix.Service != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Service").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.IPv6Prefix.Service).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	// If no prefix found
	if !result.IPPrefix.IsValid() && !result.IPv6Prefix.IPv6Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No AWS prefix found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	// Creation date if available
	if !result.CreateDate.IsZero() {
		table.SetCell(row, 0, tview.NewTableCell(" Creation Date").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.CreateDate.Format("2006-01-02")).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// Status
	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("AWS Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
