package ui

import (
	"encoding/json"
	"log/slog"
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/virustotal"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchVirusTotal(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from VirusTotal", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for VirusTotal", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "virustotal", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run virustotal")

	res, err := processor.Run(virustotal.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from VirusTotal", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "virustotal", ip)}
	}

	slog.Info("Fetching data from VirusTotal", "ip", ip)

	// Parse VirusTotal JSON response
	var vtResult virustotal.HostSearchResult
	if err := json.Unmarshal([]byte(res), &vtResult); err != nil {
		slog.Error("Failed to parse VirusTotal JSON", "error", err)

		return providerResult{text: simplifyError(err, "virustotal", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createVirusTotalTable(ip, &vtResult, false)

	return providerResult{table: table}
}

func createVirusTotalTable(ip string, result *virustotal.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " VIRUSTOTAL | Host: " + ip
	if isActive {
		headerText = " ▶ VIRUSTOTAL | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check for errors
	if result.Error != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Error").
			SetTextColor(tcell.ColorRed).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Error).
			SetTextColor(tcell.ColorRed).
			SetSelectable(false))

		return table
	}

	// Analysis Stats - most important information
	stats := result.Data.Attributes.LastAnalysisStats
	if stats.Malicious > 0 || stats.Suspicious > 0 || stats.Harmless > 0 || stats.Undetected > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Detection Results").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		if stats.Malicious > 0 {
			table.SetCell(row, 0, tview.NewTableCell("   - Malicious").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(stats.Malicious)).
				SetTextColor(tcell.ColorRed).
				SetSelectable(false))

			row++
		}

		if stats.Suspicious > 0 {
			table.SetCell(row, 0, tview.NewTableCell("   - Suspicious").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(stats.Suspicious)).
				SetTextColor(tcell.ColorYellow).
				SetSelectable(false))

			row++
		}

		if stats.Harmless > 0 {
			table.SetCell(row, 0, tview.NewTableCell("   - Harmless").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(stats.Harmless)).
				SetTextColor(tcell.ColorGreen).
				SetSelectable(false))

			row++
		}

		if stats.Undetected > 0 {
			table.SetCell(row, 0, tview.NewTableCell("   - Undetected").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(stats.Undetected)).
				SetTextColor(tcell.ColorGray).
				SetSelectable(false))

			row++
		}
	}

	// Location and Network Information
	if result.Data.Attributes.Country != "" || result.Data.Attributes.Continent != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Location").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		if result.Data.Attributes.Country != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Country").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Data.Attributes.Country).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Data.Attributes.Continent != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Continent").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Data.Attributes.Continent).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	// Network Information
	if result.Data.Attributes.Asn != 0 || result.Data.Attributes.AsOwner != "" || result.Data.Attributes.Network != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Network").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		if result.Data.Attributes.Asn != 0 {
			table.SetCell(row, 0, tview.NewTableCell("   - ASN").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(result.Data.Attributes.Asn)).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Data.Attributes.AsOwner != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - AS Owner").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Data.Attributes.AsOwner).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Data.Attributes.Network != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Network").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Data.Attributes.Network).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Data.Attributes.RegionalInternetRegistry != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - RIR").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Data.Attributes.RegionalInternetRegistry).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	// Reputation
	if result.Data.Attributes.Reputation != 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Reputation").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		repColor := tcell.ColorGreen
		if result.Data.Attributes.Reputation < 0 {
			repColor = tcell.ColorRed
		} else if result.Data.Attributes.Reputation < 50 {
			repColor = tcell.ColorYellow
		}

		table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(result.Data.Attributes.Reputation)).
			SetTextColor(repColor).
			SetSelectable(false))

		row++
	}

	// Votes
	if result.Data.Attributes.TotalVotes.Harmless > 0 || result.Data.Attributes.TotalVotes.Malicious > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Community Votes").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		if result.Data.Attributes.TotalVotes.Harmless > 0 {
			table.SetCell(row, 0, tview.NewTableCell("   - Harmless").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(result.Data.Attributes.TotalVotes.Harmless)).
				SetTextColor(tcell.ColorGreen).
				SetSelectable(false))

			row++
		}

		if result.Data.Attributes.TotalVotes.Malicious > 0 {
			table.SetCell(row, 0, tview.NewTableCell("   - Malicious").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(result.Data.Attributes.TotalVotes.Malicious)).
				SetTextColor(tcell.ColorRed).
				SetSelectable(false))
		}
	}

	return table
}
