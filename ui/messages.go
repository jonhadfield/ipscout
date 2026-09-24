package ui

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/registry"
	"github.com/jonhadfield/ipscout/runner"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

const (
	msgLookupFailedFmt = "lookup failed for %s (see " + LogFileName + " for details)"
	// maxMessageLines caps the footer lines messages may take, so the
	// results keep most of the screen
	maxMessageLines = 6
	// footerWrapMargin allows for word wrapping using more lines than a
	// message's width divided by the footer's
	footerWrapMargin = 10
	minFooterWidth   = 20
)

// failureTexts are the simplifyError results that mean a lookup failed, as
// opposed to the host not being in a provider's data or the provider being
// disabled.
var failureTexts = []string{
	ErrMsgServiceError,
	ErrMsgConnectionFailed,
	ErrMsgServiceTemporarilyUnavailable,
	ErrMsgInvalidDataFormat,
	ErrMsgAuthenticationRequired,
}

func isFailedResult(result providerResult) bool {
	return result.table == nil && slices.Contains(failureTexts, result.text)
}

func isKeyRejectedResult(result providerResult) bool {
	return result.table == nil && result.text == ErrMsgAPIKeyRejected
}

func errorLine(msg string) string {
	return "[red]ERROR[white] " + tview.Escape(msg) + "[-]"
}

// startupMessages formats the errors and warnings raised while loading
// config, such as a keyed provider enabled without an API key, for display
// for the whole session. Info messages are left to the log, as they include
// routine notes such as providers missing from the config.
func startupMessages(m *session.Messages) []string {
	m.Mu.Lock()
	defer m.Mu.Unlock()

	lines := make([]string, 0, len(m.Error)+len(m.Warning))

	for _, msg := range m.Error {
		lines = append(lines, errorLine(msg))
	}

	for _, msg := range m.Warning {
		lines = append(lines, "[yellow]WARN[white] "+tview.Escape(msg)+"[-]")
	}

	return lines
}

// lookupMessages formats the messages for one lookup: what the providers
// reported themselves, those that refused their API key, those whose lookup
// failed, and a tip if one is due.
func lookupMessages(reported, rejected, failed []string, tip string) []string {
	var lines []string

	for _, msg := range reported {
		lines = append(lines, errorLine(msg))
	}

	rejected = slices.Clone(rejected)
	slices.Sort(rejected)

	for _, name := range rejected {
		lines = append(lines, errorLine(registry.APIKeyRejectedMessage(name)))
	}

	if len(failed) > 0 {
		failed = slices.Clone(failed)
		slices.Sort(failed)

		lines = append(lines, errorLine(fmt.Sprintf(msgLookupFailedFmt, strings.Join(failed, ", "))))
	}

	if tip != "" {
		lines = append(lines, "[lightcyan]TIP[white] "+tview.Escape(tip)+"[-]")
	}

	return lines
}

// footerContent puts any messages above the key help.
func footerContent(msgs []string) string {
	if len(msgs) == 0 {
		return FooterText
	}

	return strings.Join(msgs, "\n") + "\n" + FooterText
}

// footerHeight is the number of lines the footer needs to show msgs and the
// key help at the given width.
func footerHeight(msgs []string, width int) int {
	width = max(width-footerWrapMargin, minFooterWidth)

	var lines int

	for _, msg := range msgs {
		lines += max(1, (tview.TaggedStringWidth(msg)+width-1)/width)
	}

	return min(lines, maxMessageLines) + 1
}

// tuiSignupTip returns the API key tip for a lookup that matchingResults
// providers had data for, or "" if none is due. The TUI's session holds no
// open cache between lookups, so it opens one to record the tip.
func tuiSignupTip(sess *session.Session, matchingResults int) string {
	db, err := cache.Create(sess.Logger, filepath.Join(sess.Config.Global.HomeDir, ".config", "ipscout"))
	if err != nil {
		slog.Debug("failed to open cache for tip", "error", err)

		return ""
	}

	defer func() { _ = cache.Close(sess.Logger, db) }()

	tipSess := *sess
	tipSess.Cache = db

	return runner.SignupTip(&tipSess, matchingResults)
}
