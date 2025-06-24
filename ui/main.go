package ui

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	c "github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/session"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// UI Layout Constants
const (
	// Grid dimensions
	GridRows          = 4
	GridColumns       = 2
	ProvidersColWidth = 18

	// Grid row indices
	TopBarRow  = 0
	HeaderRow  = 1
	ContentRow = 2
	FooterRow  = 3

	// Grid column indices
	ProvidersCol = 0
	ResultsCol   = 1

	// Provider list indices
	PTRProviderIndex = 0

	// File permissions
	LogFilePerms = 0o666

	// UI Messages
	PressEnterMsg   = "Press enter to load"
	PlaceholderText = "  Enter IP address or hostname"
	FooterText      = "(i) input | (p) providers | (q) quit | Ctrl+C confirm quit"
	ProvidersHeader = "Providers"
	ResultsHeader   = "Results"
	LogFileName     = "app.log"

	// Icon alternation
	emojiDocument = "📄"
	emojiGlobe    = "🌐"      // Globe icon
	emojiInvader  = "👾"      // Network icon
	emojiLaptop   = "💻"      // Shield icon
	emojiCloud    = "\u2601" // Cloud icon

	// Loading spinner
	LoadingMsg = "Loading provider data..."
)

var providerIcons = map[string]string{
	"annotated":    emojiDocument,
	"ptr":          emojiGlobe,
	"shodan":       emojiInvader,
	"ipapi":        emojiGlobe,
	"ipurl":        emojiGlobe,
	"googlebot":    emojiInvader,
	"hetzner":      emojiCloud,
	"ipqs":         emojiInvader,
	"abuseipdb":    emojiInvader,
	"virustotal":   emojiInvader,
	"aws":          emojiCloud,
	"azure":        emojiCloud,
	"azurewaf":     emojiCloud,
	"bingbot":      emojiInvader,
	"criminalip":   emojiInvader,
	"digitalocean": emojiLaptop,
	"gcp":          emojiCloud,
	"google":       emojiLaptop,
	"googlesc":     emojiLaptop,
	"icloudpr":     emojiLaptop,
	"linode":       emojiCloud,
	"ovh":          emojiCloud,
	"zscaler":      emojiCloud,
}

type providerResult struct {
	text  string
	table *tview.Table
}

type providerFunc func(string, *session.Session) providerResult

// isNoDataResult checks if the result indicates no data was found
func isNoDataResult(result providerResult) bool {
	// Check text-based results first - these are usually errors
	if result.table == nil {
		text := result.text
		// Check for exact matches
		if text == "No data found" ||
			text == "No data available" ||
			text == "Service error" ||
			text == "Connection failed" ||
			text == ErrMsgInvalidDataFormat ||
			text == "Provider not configured" ||
			text == "Authentication required" ||
			text == "Service temporarily unavailable" ||
			text == "Invalid IP address" {
			return true
		}

		// Check for provider-prefixed "no data" messages (e.g., "annotated: No data found")
		if strings.Contains(text, ": No data found") ||
			strings.Contains(text, ": No data available") ||
			strings.Contains(text, ": Service error") ||
			strings.Contains(text, ": Connection failed") ||
			strings.Contains(text, ": Provider not configured") ||
			strings.Contains(text, ": Authentication required") ||
			strings.Contains(text, ": Service temporarily unavailable") ||
			strings.Contains(text, ": Invalid IP address") {
			return true
		}

		return false
	}

	// For table results, use simpler logic
	table := result.table
	if table.GetRowCount() < 2 {
		return true // Only header row means no data
	}

	// Check for specific "no data" patterns in table cells
	for row := 1; row < table.GetRowCount(); row++ {
		for col := 0; col < table.GetColumnCount(); col++ {
			cell := table.GetCell(row, col)
			if cell != nil {
				cellText := cell.Text
				// Look for explicit "no data" patterns
				if strings.Contains(cellText, "No ") &&
					(strings.Contains(cellText, "prefix found") ||
						strings.Contains(cellText, "network found") ||
						strings.Contains(cellText, "records found") ||
						strings.Contains(cellText, "URL prefixes found") ||
						strings.Contains(cellText, "data available")) {
					return true
				}
			}
		}
	}

	return false // Table has actual data
}

// createLoadingSpinner creates an animated loading spinner
func createLoadingSpinner(app *tview.Application, text string) (*tview.TextView, chan bool) {
	spinnerChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

	spinnerView := tview.NewTextView()
	spinnerView.SetBackgroundColor(tcell.ColorBlack)
	spinnerView.SetTextColor(tcell.ColorLightCyan)
	spinnerView.SetTextAlign(tview.AlignCenter)
	spinnerView.SetBorder(false)
	spinnerView.SetDynamicColors(true)

	// Set initial text
	spinnerView.SetText(fmt.Sprintf("[lightcyan]%s %s[-]", spinnerChars[0], text))

	stopChan := make(chan bool, 1)

	go func() {
		index := 0
		ticker := time.NewTicker(120 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				currentIndex := index
				app.QueueUpdateDraw(func() {
					spinnerView.SetText(fmt.Sprintf("[lightcyan]%s %s[-]",
						spinnerChars[currentIndex], text))
				})
				index = (index + 1) % len(spinnerChars)
			}
		}
	}()

	return spinnerView, stopChan
}

// getProviderIndex returns the index of the provider in the providers slice
func getProviderIndex(providerName string, providers []string) int {
	for i, p := range providers {
		if p == providerName {
			return i
		}
	}

	return 0 // Default to first provider if not found
}

// addActiveIndicatorToTable adds the ▶ arrow to the table header
func addActiveIndicatorToTable(table *tview.Table, providerName string) {
	if table == nil {
		return
	}

	// Get the current header cell
	headerCell := table.GetCell(0, 0)
	if headerCell == nil {
		return
	}

	currentText := headerCell.Text
	// Only add arrow if it's not already there
	if !strings.HasPrefix(currentText, " ▶") {
		newText := strings.Replace(currentText, " "+strings.ToUpper(providerName), " ▶ "+strings.ToUpper(providerName), 1)
		// Handle special cases
		switch providerName {
		case "ipapi":
			newText = strings.Replace(currentText, " IPAPI", " ▶ IPAPI", 1)
		case "ipurl":
			newText = strings.Replace(currentText, " IP URL", " ▶ IP URL", 1)
		case "googlebot":
			newText = strings.Replace(currentText, " GOOGLEBOT", " ▶ GOOGLEBOT", 1)
		case "hetzner":
			newText = strings.Replace(currentText, " HETZNER", " ▶ HETZNER", 1)
		case "ipqs":
			newText = strings.Replace(currentText, " IPQS", " ▶ IPQS", 1)
		case "abuseipdb":
			newText = strings.Replace(currentText, " ABUSEIPDB", " ▶ ABUSEIPDB", 1)
		case "virustotal":
			newText = strings.Replace(currentText, " VIRUSTOTAL", " ▶ VIRUSTOTAL", 1)
		case "aws":
			newText = strings.Replace(currentText, " AWS", " ▶ AWS", 1)
		case "azure":
			newText = strings.Replace(currentText, " Azure", " ▶ Azure", 1)
		case "azurewaf":
			newText = strings.Replace(currentText, " Azure WAF", " ▶ Azure WAF", 1)
		case "gcp":
			newText = strings.Replace(currentText, " GCP", " ▶ GCP", 1)
		case "digitalocean":
			newText = strings.Replace(currentText, " DigitalOcean", " ▶ DigitalOcean", 1)
		case "criminalip":
			newText = strings.Replace(currentText, " CriminalIP", " ▶ CriminalIP", 1)
		}

		headerCell.SetText(newText)
	}
}

func OpenUI() {
	// Setup logging to app.log
	logFile, err := os.OpenFile(LogFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, LogFilePerms)
	if err != nil {
		panic(fmt.Sprintf("Failed to open log file: %v", err))
	}

	defer func() {
		if err := logFile.Close(); err != nil {
			slog.Error("Failed to close log file", "error", err)
		}
	}()

	sess, err = initConfig()
	if err != nil {
		slog.Error("Failed to initialise session", "error", err)
		panic(fmt.Sprintf("Failed to initialise session: %v", err))
	}

	// sess.Logger.
	// session.Init()
	// sess := session.Session{}

	logger := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info(c.AppNameSC + " " + helpers.SemVer + " starting")

	app := tview.NewApplication().EnableMouse(true)

	// Set k9s-inspired dark theme
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorBlack
	tview.Styles.ContrastBackgroundColor = tcell.ColorSteelBlue
	tview.Styles.MoreContrastBackgroundColor = tcell.ColorLightCyan
	tview.Styles.BorderColor = tcell.ColorSteelBlue
	tview.Styles.TitleColor = tcell.ColorLightCyan
	tview.Styles.GraphicsColor = tcell.ColorWhite
	tview.Styles.PrimaryTextColor = tcell.ColorWhite
	tview.Styles.SecondaryTextColor = tcell.ColorDarkGray
	tview.Styles.TertiaryTextColor = tcell.ColorLightCyan
	tview.Styles.InverseTextColor = tcell.ColorBlack
	tview.Styles.ContrastSecondaryTextColor = tcell.ColorDarkGray

	title := tview.NewTextView()
	title.SetText(c.AppNameSC + " " + helpers.SemVer)
	title.SetTextAlign(tview.AlignCenter)
	title.SetTextColor(tcell.ColorWhite)
	title.SetBackgroundColor(tcell.ColorBlack)
	// processor, err := New(sess)
	// if err != nil {
	// 	slog.Error("Failed to initialize processor", "error", err)
	// 	panic(fmt.Sprintf("Failed to initialize processor: %v", err))
	// }
	providerFuncs := map[string]providerFunc{
		"annotated":    fetchAnnotated,
		"ptr":          fetchPTR,
		"shodan":       fetchShodan,
		"ipapi":        fetchIPAPI,
		"ipurl":        fetchIPURL,
		"googlebot":    fetchGooglebot,
		"hetzner":      fetchHetzner,
		"ipqs":         fetchIPQS,
		"abuseipdb":    fetchAbuseIPDB,
		"virustotal":   fetchVirusTotal,
		"aws":          fetchAWS,
		"azure":        fetchAzure,
		"azurewaf":     fetchAzureWAF,
		"bingbot":      fetchBingbot,
		"criminalip":   fetchCriminalIP,
		"digitalocean": fetchDigitalOcean,
		"gcp":          fetchGCP,
		"google":       fetchGoogle,
		"googlesc":     fetchGoogleSC,
		"icloudpr":     fetchICloudPR,
		"linode":       fetchLinode,
		"ovh":          fetchOVH,
		"zscaler":      fetchZscaler,
	}
	providers := []string{"ptr", "annotated", "shodan", "ipapi", "ipurl", "googlebot", "hetzner", "ipqs", "abuseipdb", "virustotal", "aws", "azure", "azurewaf", "bingbot", "criminalip", "digitalocean", "gcp", "google", "googlesc", "icloudpr", "linode", "ovh", "zscaler"}

	providerInfo := make(map[string]providerResult)
	input := tview.NewInputField()
	input.SetPlaceholder(PlaceholderText)
	input.SetFieldBackgroundColor(tcell.ColorBlack)
	input.SetFieldTextColor(tcell.ColorWhite)
	input.SetPlaceholderTextColor(tcell.ColorWhite)
	input.SetBackgroundColor(tcell.ColorBlack)

	// Add input capture to ensure space prefix when typing starts
	input.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		// If the field is empty and user starts typing, add a space
		if input.GetText() == "" && event.Key() != tcell.KeyEnter && event.Key() != tcell.KeyEscape && event.Rune() != 0 {
			input.SetText(" ")
		}

		return event
	})

	textBox := tview.NewTextView()
	textBox.SetBorder(false)
	textBox.SetBackgroundColor(tcell.ColorBlack)
	textBox.SetTextColor(tcell.ColorWhite)
	textBox.SetScrollable(true)
	textBox.SetWrap(true)

	// Create a flex container for results that can switch between text and table
	resultsContainer := tview.NewFlex()
	resultsContainer.SetDirection(tview.FlexRow)
	resultsContainer.SetBackgroundColor(tcell.ColorBlack)

	var currentIP string

	var currentProvider string

	// Track provider data status: true = has data, false = no data, nil = not queried
	providerDataStatus := make(map[string]*bool)

	var providerDataStatusMutex sync.RWMutex

	// Declare fetchAndShow variable first, define it later after updateProviderList
	var fetchAndShow func(string, string)

	var loadAllProviders func(string)

	providerList := tview.NewList()
	providerList.SetBorder(false)
	providerList.SetBackgroundColor(tcell.ColorBlack)
	providerList.SetMainTextColor(tcell.ColorWhite)
	providerList.SetSelectedTextColor(tcell.ColorBlack)
	providerList.SetSelectedBackgroundColor(tcell.ColorLightCyan)
	providerList.SetHighlightFullLine(true)
	// Enable style tags for color markup in provider names
	providerList.SetUseStyleTags(true, false)
	// Add selection prefix
	providerList.SetSelectedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		// This will be called when enter is pressed, handled by individual item callbacks
	})

	// Function to update provider list with arrow indicator and data status colors
	updateProviderList := func(activeProvider string) {
		providerList.Clear()

		// Separate providers into successful and failed groups, maintaining original order within groups
		var successfulProviders []string

		var failedProviders []string

		providerDataStatusMutex.RLock()
		for _, p := range providers {
			dataStatus := providerDataStatus[p]
			if dataStatus != nil && !*dataStatus {
				// Provider was queried but has no data - add to failed list
				failedProviders = append(failedProviders, p)
			} else {
				// Provider has data or hasn't been queried yet - add to successful list
				successfulProviders = append(successfulProviders, p)
			}
		}
		providerDataStatusMutex.RUnlock()

		// Combine lists: successful first, then failed
		orderedProviders := successfulProviders
		orderedProviders = append(orderedProviders, failedProviders...)

		for _, p := range orderedProviders {
			var prefix string
			if p == activeProvider {
				prefix = "▶ " // Arrow for active provider
			} else {
				prefix = "  "
			}

			// Check provider data status and adjust display with color markup
			var displayName string

			providerDataStatusMutex.RLock()
			dataStatus := providerDataStatus[p]
			providerDataStatusMutex.RUnlock()
			if dataStatus != nil && !*dataStatus {
				// Provider was queried but has no data - use grey text with tview color markup
				displayName = fmt.Sprintf("[gray]%s%s %s[-]", prefix, providerIcons[p], p)
			} else {
				// Provider has data or hasn't been queried yet - normal white
				displayName = fmt.Sprintf("%s%s %s", prefix, providerIcons[p], p)
			}

			providerList.AddItem(displayName, "", 0, func(pname string) func() {
				return func() {
					if currentIP != "" {
						slog.Info("Provider selected", "provider", pname, "ip", currentIP)
						fetchAndShow(pname, currentIP)
					} else {
						slog.Error("Provider selected but no IP available", "provider", pname)

						if pname != "ptr" {
							textBox.SetText(PressEnterMsg)
						}
					}
				}
			}(p))
		}
	}

	// Function to load all providers sequentially to avoid cache lock issues
	loadAllProviders = func(ip string) {
		slog.Info("Loading all providers sequentially", "ip", ip)

		// Parse host once for all providers
		host, err := helpers.ParseHost(ip)
		if err != nil {
			slog.Error("Failed to parse host for loading", "ip", ip, "error", err)
			app.QueueUpdateDraw(func() {
				resultsContainer.Clear()
				textBox.SetText("Failed to parse host")
				resultsContainer.AddItem(textBox, 0, 1, true)
			})
			return
		}

		// Load each provider sequentially to avoid cache lock contention
		for _, providerName := range providers {
			fn, ok := providerFuncs[providerName]
			if !ok {
				// Provider function not found
				hasData := false

				providerDataStatusMutex.Lock()
				providerDataStatus[providerName] = &hasData
				providerInfo[providerName] = providerResult{text: "Provider not available"}
				providerDataStatusMutex.Unlock()
				continue
			}

			// Create a session copy for this provider
			sessCopy := *sess
			sessCopy.Host = host
			result := fn(ip, &sessCopy)

			// Store result in thread-safe manner
			providerDataStatusMutex.Lock()
			providerInfo[providerName] = result
			hasData := !isNoDataResult(result)
			providerDataStatus[providerName] = &hasData
			providerDataStatusMutex.Unlock()

			// Update the provider list after each provider loads
			app.QueueUpdateDraw(func() {
				updateProviderList(currentProvider)
			})
		}

		// After all providers are loaded, show the first one with data or PTR as fallback
		app.QueueUpdateDraw(func() {
			if currentProvider == "" {
				providerDataStatusMutex.RLock()

				for _, p := range providers {
					if status := providerDataStatus[p]; status != nil && *status {
						providerDataStatusMutex.RUnlock()

						currentProvider = p
						fetchAndShow(p, ip)
						return
					}
				}
				providerDataStatusMutex.RUnlock()
				// Fallback to PTR
				currentProvider = "ptr"

				fetchAndShow("ptr", ip)
			}
		})

		slog.Info("Finished loading all providers")
	}

	// Helper function to handle provider not found error
	handleProviderError := func(providerName string) {
		errMsg := "Provider not available"

		slog.Error("Unknown provider requested", "provider", providerName, "ip", currentIP)
		textBox.SetText(errMsg)
		resultsContainer.Clear()
		resultsContainer.AddItem(textBox, 0, 1, true)
		// Switch focus back to provider list since this is an error and maintain selection
		providerIndex := getProviderIndex(providerName, providers)
		providerList.SetCurrentItem(providerIndex)
		app.SetFocus(providerList)
	}

	// Helper function to handle text results
	handleTextResult := func(result providerResult, providerName string) {
		textBox.SetText(result.text)
		resultsContainer.AddItem(textBox, 0, 1, true)

		// If no data was found, switch focus back to provider list and maintain selection
		if isNoDataResult(result) {
			providerIndex := getProviderIndex(providerName, providers)
			providerList.SetCurrentItem(providerIndex)
			app.SetFocus(providerList)
		} else {
			app.SetFocus(textBox)
		}
	}

	// Now define fetchAndShow function
	fetchAndShow = func(providerName, ip string) {
		slog.Info("Fetching data", "ip", ip, "provider", providerName)

		fn, ok := providerFuncs[providerName]
		if !ok {
			handleProviderError(providerName)

			return
		}

		if ip == "" {
			slog.Error("Empty IP provided for fetchAndShow", "provider", providerName)

			return
		}

		// Check if we already have cached data for this provider
		providerDataStatusMutex.RLock()
		if cachedResult, exists := providerInfo[providerName]; exists {
			providerDataStatusMutex.RUnlock()

			// Update current provider and refresh provider list with arrow
			currentProvider = providerName
			updateProviderList(currentProvider)

			// Clear the results container
			resultsContainer.Clear()

			// Show cached result
			if cachedResult.table != nil {
				// Add active indicator since this table will receive focus
				addActiveIndicatorToTable(cachedResult.table, providerName)
				resultsContainer.AddItem(cachedResult.table, 0, 1, true)
				app.SetFocus(cachedResult.table)
			} else {
				handleTextResult(cachedResult, providerName)
			}
			return
		}
		providerDataStatusMutex.RUnlock()

		result := fn(ip, sess)

		// Store result in thread-safe manner
		providerDataStatusMutex.Lock()
		providerInfo[providerName] = result
		// Track whether this provider has data or not
		hasData := !isNoDataResult(result)
		providerDataStatus[providerName] = &hasData
		providerDataStatusMutex.Unlock()

		// Update current provider and refresh provider list with arrow
		currentProvider = providerName
		updateProviderList(currentProvider)

		// Clear the results container
		resultsContainer.Clear()

		// Show either table or text based on result type and handle focus
		if result.table != nil {
			// Add active indicator since this table will receive focus
			addActiveIndicatorToTable(result.table, providerName)
			resultsContainer.AddItem(result.table, 0, 1, true)
			app.SetFocus(result.table)
		} else {
			handleTextResult(result, providerName)
		}
	}

	// Initialize provider list without any active provider
	updateProviderList("")
	// Set PTR (first provider) as the default selection
	providerList.SetCurrentItem(PTRProviderIndex)
	providerList.SetSelectedFocusOnly(true)
	// Reduce spacing between items by showing main text only
	providerList.ShowSecondaryText(false)

	// Add selection change handler to show "Press enter to load" for non-PTR providers
	providerList.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		if currentIP == "" && index > PTRProviderIndex { // Not PTR and no IP entered
			textBox.SetText(PressEnterMsg)
		}
	})

	input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			inputText := strings.TrimSpace(input.GetText())
			if inputText == "" {
				slog.Error("Empty input entered by user")

				return
			}

			slog.Info("User entered input", "input", inputText)

			// Validate and resolve the input (IP address or hostname)
			_, err := helpers.ParseHost(inputText)
			if err != nil {
				slog.Error("Failed to resolve input", "input", inputText, "error", err)

				// Show error in results pane
				textBox.SetText("Invalid input")
				resultsContainer.Clear()
				resultsContainer.AddItem(textBox, 0, 1, true)

				// Reset input to placeholder
				input.SetText("")

				currentIP = ""
				currentProvider = ""

				// Reset provider data status
				providerDataStatus = make(map[string]*bool)

				updateProviderList("") // Clear arrow indicators

				// Keep focus on input for user to try again
				app.SetFocus(input)

				return
			}

			currentIP = inputText

			// Reset provider data status for new IP
			providerDataStatus = make(map[string]*bool)

			if len(providers) > 0 {
				// Show animated loading spinner
				spinner, stopSpinner := createLoadingSpinner(app, LoadingMsg)
				resultsContainer.Clear()
				resultsContainer.AddItem(spinner, 0, 1, false)

				slog.Info("Provider list", "providers", providers)
				// Load all providers in background to avoid blocking UI
				go func() {
					loadAllProviders(currentIP)
					stopSpinner <- true
					slog.Info("Finished loading all providers")
				}()
			} else {
				slog.Error("No providers available")
			}

			app.SetFocus(providerList)
		}
	})

	// Create section headers
	providersHeader := tview.NewTextView()
	providersHeader.SetText(ProvidersHeader)
	providersHeader.SetTextColor(tcell.ColorPurple)
	providersHeader.SetBackgroundColor(tcell.ColorBlack)
	providersHeader.SetTextAlign(tview.AlignCenter)

	resultsHeader := tview.NewTextView()
	resultsHeader.SetText(ResultsHeader)
	resultsHeader.SetTextColor(tcell.ColorPurple)
	resultsHeader.SetBackgroundColor(tcell.ColorBlack)
	resultsHeader.SetTextAlign(tview.AlignCenter)

	grid := tview.NewGrid()
	grid.SetRows(1, 1, 0, 1)
	grid.SetColumns(ProvidersColWidth, 0)
	grid.SetBorders(true)
	grid.SetBordersColor(tcell.ColorSteelBlue)
	grid.SetBackgroundColor(tcell.ColorBlack)

	grid.AddItem(title, TopBarRow, ProvidersCol, 1, 1, 0, 0, false)
	grid.AddItem(input, TopBarRow, ResultsCol, 1, 1, 0, 0, true)
	grid.AddItem(providersHeader, HeaderRow, ProvidersCol, 1, 1, 0, 0, false)
	grid.AddItem(resultsHeader, HeaderRow, ResultsCol, 1, 1, 0, 0, false)
	grid.AddItem(providerList, ContentRow, ProvidersCol, 1, 1, 0, 0, false)
	grid.AddItem(resultsContainer, ContentRow, ResultsCol, 1, 1, 0, 0, false)

	footer := tview.NewTextView()
	footer.SetDynamicColors(true)
	footer.SetTextAlign(tview.AlignCenter)
	footer.SetBackgroundColor(tcell.ColorBlack)
	footer.SetTextColor(tcell.ColorDarkGray)
	footer.SetText(FooterText)
	grid.AddItem(footer, FooterRow, ProvidersCol, 1, GridColumns, 0, 0, false)

	pages := tview.NewPages()
	pages.AddPage("main", grid, true, true)

	quitModal := tview.NewModal()
	quitModal.SetText("🚪Do you want to quit? (Y/N)")
	quitModal.SetTextColor(tcell.ColorWhite)
	quitModal.SetBackgroundColor(tcell.ColorBlack)
	quitModal.AddButtons([]string{"Yes", "No"})
	quitModal.SetButtonBackgroundColor(tcell.ColorSteelBlue)
	quitModal.SetButtonTextColor(tcell.ColorWhite)

	quitModal.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'y', 'Y':
			slog.Info("User confirmed quit via keyboard (Y)")

			app.Stop()

			return nil
		case 'n', 'N':
			slog.Info("User cancelled quit via keyboard (N)")
			pages.HidePage("quit")

			app.SetFocus(grid)

			return nil
		}

		return event
	})

	quitModal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
		if buttonIndex == 0 {
			slog.Info("User confirmed quit via modal")
			app.Stop()
		} else {
			slog.Info("User cancelled quit via modal")
			pages.HidePage("quit")
			app.SetFocus(grid)
		}
	})

	pages.AddPage("quit", quitModal, true, false)

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		// Always allow Ctrl+C regardless of focus
		if event.Key() == tcell.KeyCtrlC {
			slog.Info("User pressed Ctrl+C, showing quit confirmation")
			pages.ShowPage("quit")

			app.SetFocus(quitModal)

			return nil
		}

		// Only handle navigation keys when input field is NOT focused
		if app.GetFocus() != input {
			switch event.Rune() {
			case 'q', 'Q':
				slog.Info("User quit application with 'q' key")

				app.Stop()

				return nil
			case 'i':
				input.SetText(" ")

				currentIP = ""
				currentProvider = ""

				// Reset provider data status
				providerDataStatus = make(map[string]*bool)

				updateProviderList("") // Clear arrow indicators

				resultsContainer.Clear()

				app.SetFocus(input)

				return nil
			case 'p':
				// Return to the last selected provider if we have one
				if currentProvider != "" {
					providerIndex := getProviderIndex(currentProvider, providers)
					providerList.SetCurrentItem(providerIndex)
				}

				app.SetFocus(providerList)

				return nil
			}

			// Handle arrow keys
			switch event.Key() {
			case tcell.KeyLeft:
				// Return to the last selected provider if we have one
				if currentProvider != "" {
					providerIndex := getProviderIndex(currentProvider, providers)
					providerList.SetCurrentItem(providerIndex)
				}

				app.SetFocus(providerList)

				return nil
			}
		}

		return event
	})

	currentIP = strings.TrimSpace(input.GetText())
	if len(providers) > 0 && currentIP != "" {
		fetchAndShow(providers[0], currentIP)
	}

	if err := app.SetRoot(pages, true).Run(); err != nil {
		slog.Error("Application error", "error", err)
		panic(err)
	}

	slog.Info(c.AppNameSC + " " + helpers.SemVer + " shutdown complete")
}
