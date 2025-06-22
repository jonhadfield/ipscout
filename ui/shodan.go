package ui

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/shodan"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchShodan(ip string, sess *session.Session) providerResult {
	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Shodan", "ip", ip, "error", err)

		return providerResult{text: fmt.Sprintf("Error parsing host for Shodan: %v", err)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run shodan")

	res, err := processor.Run(shodan.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Shodan", "ip", ip, "error", err)

		return providerResult{text: fmt.Sprintf("Error fetching data for %s from Shodan: %v", ip, err)}
	}

	slog.Info("Fetching data from Shodan", "ip", ip)

	// Parse Shodan JSON response
	var shodanResult shodan.HostSearchResult
	if err := json.Unmarshal([]byte(res), &shodanResult); err != nil {
		slog.Error("Failed to parse Shodan JSON", "error", err)

		return providerResult{text: res} // fallback to raw data
	}

	// Create tview table
	table := createShodanTable(&shodanResult)

	return providerResult{table: table}
}

func createShodanTable(result *shodan.HostSearchResult) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header
	table.SetCell(row, 0, tview.NewTableCell(" SHODAN | Host: "+result.IPStr).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// WHOIS info
	if result.LastUpdate != "" || result.Org != "" || result.CountryName != "" { //nolint:nestif
		table.SetCell(row, 0, tview.NewTableCell(" WHOIS").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		if result.LastUpdate != "" {
			table.SetCell(row, 1, tview.NewTableCell(result.LastUpdate).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
		}

		row++

		if result.Org != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Org").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Org).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Isp != "" && result.Isp != result.Org {
			table.SetCell(row, 0, tview.NewTableCell("   - ISP").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Isp).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Asn != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - ASN").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Asn).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

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

		if result.RegionCode != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Region").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.RegionCode).
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

			table.SetCell(row, 0, tview.NewTableCell("   - Location").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(coords).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	// Ports
	if len(result.Ports) > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Ports").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(len(result.Ports))).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		for _, port := range result.Ports {
			table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(port)+"/tcp").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	// Service Details from Data array
	if len(result.Data) > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Services").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(len(result.Data))).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++

		for _, data := range result.Data {
			portInfo := strconv.Itoa(data.Port) + "/" + data.Transport

			table.SetCell(row, 0, tview.NewTableCell("   - Port").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(portInfo).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++

			if data.Org != "" {
				table.SetCell(row, 0, tview.NewTableCell("     - Org").
					SetTextColor(tcell.ColorGray).
					SetSelectable(false))
				table.SetCell(row, 1, tview.NewTableCell(data.Org).
					SetTextColor(tcell.ColorGray).
					SetSelectable(false))

				row++
			}

			if len(data.Domains) > 0 {
				table.SetCell(row, 0, tview.NewTableCell("     - Domains").
					SetTextColor(tcell.ColorGray).
					SetSelectable(false))
				table.SetCell(row, 1, tview.NewTableCell(strings.Join(data.Domains, ", ")).
					SetTextColor(tcell.ColorGray).
					SetSelectable(false))

				row++ //nolint:ineffassign
			}

			if data.Timestamp != "" {
				table.SetCell(row, 0, tview.NewTableCell("     - Last Seen").
					SetTextColor(tcell.ColorGray).
					SetSelectable(false))
				table.SetCell(row, 1, tview.NewTableCell(data.Timestamp).
					SetTextColor(tcell.ColorGray).
					SetSelectable(false))

				row++
			}
		}
	}

	// Domains
	if len(result.Domains) > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Domains").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(strings.Join(result.Domains, ", ")).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// Hostnames
	if len(result.Hostnames) > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Hostnames").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(strings.Join(result.Hostnames, ", ")).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	// Tags (if any)
	if len(result.Tags) > 0 {
		var tagStrings []string

		for _, tag := range result.Tags {
			if str, ok := tag.(string); ok {
				tagStrings = append(tagStrings, str)
			}
		}

		if len(tagStrings) > 0 {
			table.SetCell(row, 0, tview.NewTableCell(" Tags").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(strings.Join(tagStrings, ", ")).
				SetTextColor(tcell.ColorYellow).
				SetSelectable(false))

			row++ //nolint:ineffassign,wastedassign
		}
	}

	return table
}
