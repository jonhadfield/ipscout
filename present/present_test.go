package present

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

const (
	semVerTest    = "1.2.3"
	priorityFirst = int32(1)
)

// newTestSession builds a minimal session.Session suitable for present tests.
func newTestSession(style string) session.Session {
	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	sess := session.Session{
		Logger: lg,
		Stats:  session.CreateStats(),
	}
	sess.App.SemVer = semVerTest
	sess.Config.Global.Style = style

	return sess
}

func TestCSV(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`{
		"shodan": {"asn": "AS15169", "org": "Google LLC"},
		"abuseipdb": {"score": 0}
	}`)

	require.NoError(t, CSV(&raw))
}

func TestCSVNonObjectProviderData(t *testing.T) {
	t.Parallel()

	// Provider value is an array, not a flat object, exercising the fallback path.
	raw := json.RawMessage(`{"annotated": ["one", "two"]}`)

	require.NoError(t, CSV(&raw))
}

func TestCSVInvalidJSON(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`not-json`)

	require.Error(t, CSV(&raw))
}

func TestJSON(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`{"shodan":{"asn":"AS15169"}}`)

	require.NoError(t, JSON(&raw))
}

func TestJSONInvalid(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`{invalid`)

	require.Error(t, JSON(&raw))
}

func TestOuterTableStyle(t *testing.T) {
	t.Parallel()

	styles := []string{txtASCII, txtYellow, txtCyan, "", "unknown"}
	for _, style := range styles {
		sess := newTestSession(style)
		ts := OuterTableStyle(sess)
		require.NotEmpty(t, ts.Name)
	}
}

func TestInnerTableStyle(t *testing.T) {
	t.Parallel()

	styles := []string{txtASCII, txtYellow, txtRed, txtGreen, txtBlue, txtCyan, "", "unknown"}
	for _, style := range styles {
		sess := newTestSession(style)
		ts := InnerTableStyle(sess)
		require.NotEmpty(t, ts.Name)
	}
}

func TestTables(t *testing.T) {
	t.Parallel()

	sess := newTestSession(txtASCII)

	inner := table.NewWriter()
	inner.AppendHeader(table.Row{"key", "value"})
	inner.AppendRow(table.Row{"asn", "AS15169"})

	priority := priorityFirst
	tws := []providers.TableWithPriority{
		{Table: &inner, Priority: &priority},
		{Table: &inner, Priority: nil},
	}

	require.NotPanics(t, func() { Tables(&sess, tws) })
}
