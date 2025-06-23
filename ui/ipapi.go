package ui

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/ipapi"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchIPAPI(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from IPAPI", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for IPAPI", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "ipapi", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run ipapi")

	res, err := processor.Run(ipapi.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from IPAPI", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "ipapi", ip)}
	}

	slog.Info("Fetching data from IPAPI", "ip", ip)

	// Parse IPAPI JSON response
	var ipapiResult ipapi.HostSearchResult
	if err := json.Unmarshal([]byte(res), &ipapiResult); err != nil {
		slog.Error("Failed to parse IPAPI JSON", "error", err)

		return providerResult{text: simplifyError(err, "ipapi", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createIPAPITable(&ipapiResult, false)

	return providerResult{table: table}
}

func createIPAPITable(result *ipapi.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " IPAPI | Host: " + result.IP
	if isActive {
		headerText = " ▶ IPAPI | Host: " + result.IP
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Location Information
	table.SetCell(row, 0, tview.NewTableCell(" Location").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))

	row++

	if result.CountryName != "" {
		countryText := result.CountryName
		if result.CountryCode != "" {
			countryText += " (" + result.CountryCode + ")"
		}

		table.SetCell(row, 0, tview.NewTableCell("   - Country").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(countryText).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.Region != "" {
		table.SetCell(row, 0, tview.NewTableCell("   - Region").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Region+" ("+result.RegionCode+")").
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

	if result.Postal != "" {
		table.SetCell(row, 0, tview.NewTableCell("   - Postal Code").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Postal).
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

	// Network Information
	if result.Asn != "" || result.Org != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Network").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		if result.Asn != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - ASN").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Asn).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Org != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Organization").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Org).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Hostname != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Hostname").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Hostname).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	// Country Details
	hasCountryDetails := result.CountryCapital != "" || result.CountryTld != "" ||
		result.CountryArea > 0 || result.CountryPopulation > 0 || result.InEu

	if hasCountryDetails {
		table.SetCell(row, 0, tview.NewTableCell(" Country Details").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.CountryCapital != "" {
		table.SetCell(row, 0, tview.NewTableCell("   - Capital").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.CountryCapital).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.CountryTld != "" {
		table.SetCell(row, 0, tview.NewTableCell("   - TLD").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.CountryTld).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.CountryArea > 0 {
		table.SetCell(row, 0, tview.NewTableCell("   - Area").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%.0f km²", result.CountryArea)).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.CountryPopulation > 0 {
		table.SetCell(row, 0, tview.NewTableCell("   - Population").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(result.CountryPopulation)).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.InEu {
		table.SetCell(row, 0, tview.NewTableCell("   - EU Member").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell("Yes").
			SetTextColor(tcell.ColorGreen).
			SetSelectable(false))

		row++
	}

	// Time & Currency
	hasTimeOrCurrency := result.Timezone != "" || result.Currency != "" ||
		result.UtcOffset != "" || result.Languages != "" || result.CountryCallingCode != ""

	if hasTimeOrCurrency {
		table.SetCell(row, 0, tview.NewTableCell(" Time & Currency").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.Timezone != "" {
		table.SetCell(row, 0, tview.NewTableCell("   - Timezone").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Timezone).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.UtcOffset != "" {
		table.SetCell(row, 0, tview.NewTableCell("   - UTC Offset").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.UtcOffset).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.Currency != "" {
		currencyText := result.Currency
		if result.CurrencyName != "" {
			currencyText += " (" + result.CurrencyName + ")"
		}

		table.SetCell(row, 0, tview.NewTableCell("   - Currency").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(currencyText).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.Languages != "" {
		table.SetCell(row, 0, tview.NewTableCell("   - Languages").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Languages).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.CountryCallingCode != "" {
		table.SetCell(row, 0, tview.NewTableCell("   - Calling Code").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.CountryCallingCode).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
	}

	return table
}
