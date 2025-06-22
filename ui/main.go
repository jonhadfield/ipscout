package ui

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

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
	AppTitle        = "IPScout v0.0.1"
	ProvidersHeader = "Providers"
	ResultsHeader   = "Results"
	LogFileName     = "app.log"

	// Icon alternation
	emojiGlobe   = "🌐" // Globe icon
	emojiInvader = "👾" // Network icon
	emojiShield  = "🌐" // Shield icon
)

var providerIcons = map[string]string{
	"annotated": emojiShield,
	"ptr":       emojiGlobe,
	"shodan":    emojiInvader,
}

type providerResult struct {
	text  string
	table *tview.Table
}

type providerFunc func(string, *session.Session) providerResult

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

	slog.Info("Application starting")

	app := tview.NewApplication()

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
	title.SetText(AppTitle)
	title.SetTextAlign(tview.AlignCenter)
	title.SetTextColor(tcell.ColorWhite)
	title.SetBackgroundColor(tcell.ColorBlack)
	// processor, err := New(sess)
	// if err != nil {
	// 	slog.Error("Failed to initialize processor", "error", err)
	// 	panic(fmt.Sprintf("Failed to initialize processor: %v", err))
	// }
	providerFuncs := map[string]providerFunc{
		"annotated": fetchAnnotated,
		"ptr":       fetchPTR,
		"shodan":    fetchShodan,
	}
	providers := []string{"ptr", "annotated", "shodan"}

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

	// Declare fetchAndShow variable first, define it later after updateProviderList
	var fetchAndShow func(string, string)

	providerList := tview.NewList()
	providerList.SetBorder(false)
	providerList.SetBackgroundColor(tcell.ColorBlack)
	providerList.SetMainTextColor(tcell.ColorWhite)
	providerList.SetSelectedTextColor(tcell.ColorBlack)
	providerList.SetSelectedBackgroundColor(tcell.ColorLightCyan)
	providerList.SetHighlightFullLine(true)
	// Add selection prefix
	providerList.SetSelectedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		// This will be called when enter is pressed, handled by individual item callbacks
	})

	// Function to update provider list with arrow indicator
	updateProviderList := func(activeProvider string) {
		providerList.Clear()

		for _, p := range providers {
			var prefix string
			if p == activeProvider {
				prefix = "▶ " // Arrow for active provider
			} else {
				prefix = "  "
			}

			displayName := fmt.Sprintf("%s%s %s", prefix, providerIcons[p], p)

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

	// Now define fetchAndShow function
	fetchAndShow = func(providerName, ip string) {
		slog.Info("Fetching data", "ip", ip, "provider", providerName)

		if fn, ok := providerFuncs[providerName]; ok {
			if ip == "" {
				slog.Error("Empty IP provided for fetchAndShow", "provider", providerName)

				return
			}

			result := fn(ip, sess)
			providerInfo[providerName] = result

			// Update current provider and refresh provider list with arrow
			currentProvider = providerName
			updateProviderList(currentProvider)

			// Clear the results container
			resultsContainer.Clear()

			// Show either table or text based on result type
			if result.table != nil {
				resultsContainer.AddItem(result.table, 0, 1, true)
				app.SetFocus(result.table)
			} else {
				textBox.SetText(result.text)
				resultsContainer.AddItem(textBox, 0, 1, true)
				app.SetFocus(textBox)
			}
		} else {
			errMsg := fmt.Sprintf("no provider for %s", providerName)
			slog.Error("Unknown provider requested", "provider", providerName, "ip", ip)
			textBox.SetText(errMsg)
			resultsContainer.Clear()
			resultsContainer.AddItem(textBox, 0, 1, true)
			app.SetFocus(textBox)
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
			currentIP = strings.TrimSpace(input.GetText())
			if currentIP == "" {
				slog.Error("Empty IP entered by user")

				return
			}

			slog.Info("User entered IP", "ip", currentIP)

			if len(providers) > 0 {
				slog.Info("Provider list", "providers", providers)
				// Always default to PTR (first provider) and load it
				providerList.SetCurrentItem(PTRProviderIndex)
				fetchAndShow("ptr", currentIP)
				slog.Info("Finished fetchAndShow with PTR provider")
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
	quitModal.SetText("󰗼 Do you want to quit? (Y/N)")
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

				updateProviderList("") // Clear arrow indicators

				resultsContainer.Clear()

				app.SetFocus(input)

				return nil
			case 'p':
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

	slog.Info("Application shutdown complete")
}
