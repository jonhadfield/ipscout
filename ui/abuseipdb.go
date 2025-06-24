package ui

import (
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/abuseipdb"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

const (
	highAbuseScoreThreshold   = 75
	mediumAbuseScoreThreshold = 50
)

func fetchAbuseIPDB(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from AbuseIPDB", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for AbuseIPDB", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "abuseipdb", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run abuseipdb")

	res, err := processor.Run(abuseipdb.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from AbuseIPDB", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "abuseipdb", ip)}
	}

	slog.Info("Fetching data from AbuseIPDB", "ip", ip)

	// Parse AbuseIPDB JSON response
	var abuseResult abuseipdb.HostSearchResult
	if err := json.Unmarshal([]byte(res), &abuseResult); err != nil {
		slog.Error("Failed to parse AbuseIPDB JSON", "error", err)

		return providerResult{text: simplifyError(err, "abuseipdb", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createAbuseIPDBTable(ip, &abuseResult, false)

	return providerResult{table: table}
}

func createAbuseIPDBTable(ip string, result *abuseipdb.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " ABUSEIPDB | Host: " + ip
	if isActive {
		headerText = " ▶ ABUSEIPDB | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Abuse Confidence Score - most important metric
	abuseScore := int(result.Data.AbuseConfidenceScore)

	table.SetCell(row, 0, tview.NewTableCell(" Abuse Score").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))

	scoreColor := tcell.ColorGreen
	if abuseScore >= highAbuseScoreThreshold {
		scoreColor = tcell.ColorRed
	} else if abuseScore >= mediumAbuseScoreThreshold {
		scoreColor = tcell.ColorYellow
	}

	table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(abuseScore)+"%").
		SetTextColor(scoreColor).
		SetSelectable(false))

	row++

	// Location Information
	if result.Data.CountryCode != "" || result.Data.CountryName != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Location").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		if result.Data.CountryName != "" {
			countryText := result.Data.CountryName
			if result.Data.CountryCode != "" {
				countryText += " (" + result.Data.CountryCode + ")"
			}

			table.SetCell(row, 0, tview.NewTableCell("   - Country").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(countryText).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	// Network Information
	if result.Data.Isp != "" || result.Data.Domain != "" || len(result.Data.Hostnames) > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Network").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		if result.Data.Isp != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - ISP").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Data.Isp).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Data.Domain != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Domain").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Data.Domain).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if len(result.Data.Hostnames) > 0 {
			table.SetCell(row, 0, tview.NewTableCell("   - Hostnames").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(strings.Join(result.Data.Hostnames, ", ")).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	// Usage Information
	if result.Data.UsageType != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Usage Type").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Data.UsageType).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// Risk Indicators
	addAbuseRiskIndicators(table, result, &row)

	// Reports Information
	if result.Data.TotalReports > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Reports").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		table.SetCell(row, 0, tview.NewTableCell("   - Total Reports").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(result.Data.TotalReports)).
			SetTextColor(tcell.ColorRed).
			SetSelectable(false))

		row++

		if result.Data.NumDistinctUsers > 0 {
			table.SetCell(row, 0, tview.NewTableCell("   - Distinct Users").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(result.Data.NumDistinctUsers)).
				SetTextColor(tcell.ColorRed).
				SetSelectable(false))

			row++
		}

		if !result.Data.LastReportedAt.IsZero() {
			table.SetCell(row, 0, tview.NewTableCell("   - Last Reported").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Data.LastReportedAt.Format("2006-01-02")).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
		}
	}

	return table
}

func addAbuseRiskIndicators(table *tview.Table, result *abuseipdb.HostSearchResult, row *int) {
	hasRiskIndicators := result.Data.IsTor || result.Data.IsWhitelisted
	if !hasRiskIndicators {
		return
	}

	table.SetCell(*row, 0, tview.NewTableCell(" Risk Indicators").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))

	*row++

	if result.Data.IsTor {
		table.SetCell(*row, 0, tview.NewTableCell("   - Tor Exit Node").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(*row, 1, tview.NewTableCell("Yes").
			SetTextColor(tcell.ColorRed).
			SetSelectable(false))

		*row++
	}

	if result.Data.IsWhitelisted {
		table.SetCell(*row, 0, tview.NewTableCell("   - Whitelisted").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(*row, 1, tview.NewTableCell("Yes").
			SetTextColor(tcell.ColorGreen).
			SetSelectable(false))
	}
}
