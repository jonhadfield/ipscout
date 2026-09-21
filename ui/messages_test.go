package ui

import (
	"strings"
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
	"github.com/stretchr/testify/require"
)

func TestIsFailedResult(t *testing.T) {
	t.Parallel()

	for _, text := range failureTexts {
		require.True(t, isFailedResult(providerResult{text: text}), text)
	}

	// routine outcomes are not failures
	for _, text := range []string{
		"shodan: " + ErrMsgNoDataFound,
		ErrMsgNoDataAvailable,
		ErrMsgProviderNotConfigured,
		ErrMsgInvalidIPAddress,
	} {
		require.False(t, isFailedResult(providerResult{text: text}), text)
	}

	require.False(t, isFailedResult(providerResult{table: tview.NewTable()}))
}

func TestStartupMessages(t *testing.T) {
	t.Parallel()

	m := &session.Messages{}
	m.AddInfo("Annotated provider not defined in config")
	m.AddWarn("disabled AbuseIPDB in your config")
	m.AddError("Shodan is enabled but has no API key: set SHODAN_API_KEY")

	lines := startupMessages(m)

	// errors first, then warnings; info is left to the log
	require.Len(t, lines, 2)
	require.True(t, strings.HasPrefix(lines[0], "[red]ERROR"))
	require.Contains(t, lines[0], "SHODAN_API_KEY")
	require.True(t, strings.HasPrefix(lines[1], "[yellow]WARN"))
}

func TestLookupMessages(t *testing.T) {
	t.Parallel()

	require.Empty(t, lookupMessages(nil, ""))

	lines := lookupMessages([]string{"ptr", "internetdb"}, "API keys unlock more [see config]")
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], "lookup failed for internetdb, ptr (see app.log for details)")
	require.True(t, strings.HasPrefix(lines[1], "[lightcyan]TIP"))
	// brackets in message text must not be read as colour tags
	require.Equal(t, "TIP API keys unlock more [see config]", strings.TrimSpace(stripTags(lines[1])))
}

func stripTags(s string) string {
	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetText(s)

	return tv.GetText(true)
}

func TestFooterContentAndHeight(t *testing.T) {
	t.Parallel()

	require.Equal(t, FooterText, footerContent(nil))
	require.Equal(t, 1, footerHeight(nil, 100))

	msgs := []string{errorLine("short"), errorLine(strings.Repeat("x", 250))}
	require.Equal(t, "[red]ERROR[white] short[-]\n"+msgs[1]+"\n"+FooterText, footerContent(msgs))

	// one line for the short message, three for the long one at width 100
	// (90 after the wrap margin), plus the key help
	require.Equal(t, 5, footerHeight(msgs, 100))

	// capped so results keep the screen
	many := make([]string, 20)
	for i := range many {
		many[i] = errorLine("message")
	}

	require.Equal(t, maxMessageLines+1, footerHeight(many, 100))
}
