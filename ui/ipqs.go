package ui

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/ipqs"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

const (
	highFraudScoreThreshold   = 75
	mediumFraudScoreThreshold = 50
)

func fetchIPQS(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from IPQS", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for IPQS", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "ipqs", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run ipqs")

	res, err := processor.Run(ipqs.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from IPQS", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "ipqs", ip)}
	}

	slog.Info("Fetching data from IPQS", "ip", ip)

	// Parse IPQS JSON response
	var ipqsResult ipqs.HostSearchResult
	if err := json.Unmarshal([]byte(res), &ipqsResult); err != nil {
		slog.Error("Failed to parse IPQS JSON", "error", err)

		return providerResult{text: simplifyError(err, "ipqs", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createIPQSTable(ip, &ipqsResult, false)

	return providerResult{table: table}
}

func addRiskIndicators(table *tview.Table, result *ipqs.HostSearchResult, row *int) {
	hasRiskIndicators := result.Proxy || result.Vpn || result.Tor || result.RecentAbuse || result.BotStatus || result.IsCrawler
	if !hasRiskIndicators {
		return
	}

	table.SetCell(*row, 0, tview.NewTableCell(" Risk Indicators").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))

	*row++

	if result.Proxy {
		table.SetCell(*row, 0, tview.NewTableCell("   - Proxy").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(*row, 1, tview.NewTableCell("Yes").
			SetTextColor(tcell.ColorRed).
			SetSelectable(false))

		*row++
	}

	if result.Vpn {
		table.SetCell(*row, 0, tview.NewTableCell("   - VPN").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(*row, 1, tview.NewTableCell("Yes").
			SetTextColor(tcell.ColorRed).
			SetSelectable(false))

		*row++
	}

	if result.Tor {
		table.SetCell(*row, 0, tview.NewTableCell("   - Tor").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(*row, 1, tview.NewTableCell("Yes").
			SetTextColor(tcell.ColorRed).
			SetSelectable(false))

		*row++
	}

	if result.RecentAbuse {
		table.SetCell(*row, 0, tview.NewTableCell("   - Recent Abuse").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(*row, 1, tview.NewTableCell("Yes").
			SetTextColor(tcell.ColorRed).
			SetSelectable(false))

		*row++
	}

	if result.BotStatus {
		table.SetCell(*row, 0, tview.NewTableCell("   - Bot Status").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(*row, 1, tview.NewTableCell("Yes").
			SetTextColor(tcell.ColorRed).
			SetSelectable(false))

		*row++
	}

	if result.IsCrawler {
		table.SetCell(*row, 0, tview.NewTableCell("   - Crawler").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(*row, 1, tview.NewTableCell("Yes").
			SetTextColor(tcell.ColorGreen).
			SetSelectable(false))
	}
}

func createIPQSTable(ip string, result *ipqs.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " IPQS | Host: " + ip
	if isActive {
		headerText = " ▶ IPQS | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have any data
	if !result.Success {
		table.SetCell(row, 0, tview.NewTableCell(" No data available").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		if result.Message != "" {
			table.SetCell(row, 1, tview.NewTableCell(result.Message).
				SetTextColor(tcell.ColorYellow).
				SetSelectable(false))
		}

		return table
	}

	// Fraud Score - most important metric
	table.SetCell(row, 0, tview.NewTableCell(" Fraud Score").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))

	fraudColor := tcell.ColorGreen
	if result.FraudScore >= highFraudScoreThreshold {
		fraudColor = tcell.ColorRed
	} else if result.FraudScore >= mediumFraudScoreThreshold {
		fraudColor = tcell.ColorYellow
	}

	table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(result.FraudScore)+"/100").
		SetTextColor(fraudColor).
		SetSelectable(false))

	row++

	// Location Information
	if result.CountryCode != "" || result.Region != "" || result.City != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Location").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		if result.CountryCode != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Country").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.CountryCode).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Region != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Region").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Region).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.City != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - City").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.City).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Latitude != 0 || result.Longitude != 0 {
			coords := fmt.Sprintf("%.4f, %.4f", result.Latitude, result.Longitude)

			table.SetCell(row, 0, tview.NewTableCell("   - Coordinates").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(coords).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	// Network Information
	if result.Isp != "" || result.Organization != "" || result.Asn != 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Network").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		if result.Isp != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - ISP").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Isp).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Organization != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Organization").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Organization).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Asn != 0 {
			table.SetCell(row, 0, tview.NewTableCell("   - ASN").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(result.Asn)).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Host != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Hostname").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Host).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	// Risk Indicators
	addRiskIndicators(table, result, &row)

	return table
}
