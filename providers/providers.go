package providers

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/jonhadfield/ipscout/session"
)

const DefaultUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125."

var (
	ErrFailedToFetchData   = errors.New("failed to fetch data")
	ErrNoDataFound         = errors.New("no data found")
	ErrNoMatchFound        = errors.New("no match found")
	ErrForbiddenByProvider = errors.New("forbidden by provider")
	CacheProviderPrefix    = "provider_"
	CacheKeySHALen         = 16
)

func AgeToHours(age string) (int64, error) {
	if age == "" {
		return 0, nil
	}

	age = strings.ToLower(age)
	multiplier := map[string]int{
		"h": 1,
		"d": 24,
		"w": 24 * 7,
		"m": 24 * 30,
		"y": 24 * 365,
	}

	var ageNum int64

	for k, v := range multiplier {
		if strings.HasSuffix(age, k) {
			age = strings.TrimSuffix(age, k)

			var err error

			ageNum, err = strconv.ParseInt(age, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("error parsing age: %w", err)
			}

			ageNum *= int64(v)

			break
		}
	}

	return ageNum, nil
}

// PortNetworkMatch returns true if the incomingPort matches any of the matchPorts
func PortNetworkMatch(incomingPort string, matchPorts []string) bool {
	if len(matchPorts) == 0 {
		// if len(matchPorts) == 0 || matchPorts[0] == "[]" {
		return true
	}

	for _, p := range matchPorts {
		splitMatch := splitPortTransport(p)
		splitIncomingPort := splitPortTransport(incomingPort)

		// most specific first
		switch {
		case splitIncomingPort.port != "" && splitIncomingPort.transport != "" && splitMatch.port == splitIncomingPort.port && splitMatch.transport == splitIncomingPort.transport:
			// if both parts of match incomingPort are set and both match then return true
			return true
		case splitIncomingPort.port != "" && splitIncomingPort.transport != "" && splitMatch.transport == "" && splitMatch.port == splitIncomingPort.port && splitMatch.transport != splitIncomingPort.transport:
			// if both parts of match incomingPort are set and only port to match is set matches then return true
			return true
		case splitIncomingPort.port != "" && splitIncomingPort.transport != "" && splitMatch.port == "" && splitMatch.transport == splitIncomingPort.transport:
			// if both parts of match incomingPort are set and only transport matches then return true
			return true
		case splitIncomingPort.transport == "" && splitIncomingPort.port != "" && splitMatch.port == splitIncomingPort.port:
			// if only incomingPort is set, then only incomingPort needs to match
			return true
		case splitIncomingPort.port == "" && splitIncomingPort.transport != "" && splitMatch.transport == splitIncomingPort.transport:
			// if only transport is set, then only transport needs to match
			return true
		}
	}

	return false
}

// portAgeCheck returns true if the port is within the max age
func portAgeCheck(portConfirmedTime string, timeFormat string, maxAge string) (bool, error) {
	switch {
	case portConfirmedTime == "":
		return false, fmt.Errorf("no port confirmed time provided")
	case timeFormat == "":
		return false, fmt.Errorf("no time format provided")
	}

	// if no age filter provided, then return true
	if maxAge == "" {
		return true, nil
	}

	var confirmedTime time.Time

	var err error

	maxAgeHours, err := AgeToHours(maxAge)
	if err != nil {
		return false, fmt.Errorf("error parsing max-age: %w", err)
	}

	confirmedTime, err = time.Parse(timeFormat, portConfirmedTime)
	if err != nil {
		return false, fmt.Errorf("error parsing confirmed time: %w", err)
	}

	if confirmedTime.After(time.Now().Add(-time.Duration(maxAgeHours) * time.Hour)) {
		return true, nil
	}

	return false, nil
}

type PortMatchFilterInput struct {
	Provider            string
	IncomingPort        string
	Logger              *slog.Logger
	MatchPorts          []string
	ConfirmedDate       string
	ConfirmedDateFormat string
	MaxAge              string
}

// PortMatchFilter returns true by default, and false if either age or netmatch is specified
// and doesn't match
func PortMatchFilter(in PortMatchFilterInput) (ageMatch, netMatch bool, err error) {
	switch in.IncomingPort {
	case "":
		netMatch = true
	default:
		netMatch = PortNetworkMatch(in.IncomingPort, in.MatchPorts)
	}

	switch {
	case in.ConfirmedDate == "" && in.ConfirmedDateFormat == "":
		ageMatch = true
	case in.ConfirmedDate == "" || in.ConfirmedDateFormat == "":
		return false, false, fmt.Errorf("both confirmed date and format must be specified")
	default:
		ageMatch, err = portAgeCheck(in.ConfirmedDate, in.ConfirmedDateFormat, in.MaxAge)
		if err != nil {
			return false, false, fmt.Errorf("error checking port age: %w", err)
		}
	}

	return ageMatch, netMatch, nil
}

func PreProcessValueOutput(sess *session.Session, in string) string {
	out := strings.TrimSpace(in)

	// abbreviate output value if it exceeds max value chars
	if sess.Config.Global.MaxValueChars > 0 {
		if len(out) > int(sess.Config.Global.MaxValueChars) {
			out = out[:sess.Config.Global.MaxValueChars] + "..."
		}
	}

	return out
}

type PortTransport struct {
	port      string
	transport string
}

func splitPortTransport(portTransport string) (pt PortTransport) {
	parts := strings.Split(portTransport, "/")

	switch len(parts) {
	case 1:
		if isPort(parts[0]) {
			pt.port = parts[0]
		} else if isTransport(parts[0]) {
			pt.transport = parts[0]
		}
	case 2:
		if isPort(parts[0]) && isTransport(parts[1]) {
			pt.port = parts[0]
			pt.transport = parts[1]
		}
	}

	return pt
}

var validTransports = []string{"tcp", "udp", "icmp"}

func isPort(in any) bool {
	switch v := in.(type) {
	case string:
		var cint int

		var err error

		if cint, err = strconv.Atoi(v); err != nil {
			return false
		}

		return isPort(cint)
	case int:
		if v > 0 && v < 65535 {
			return true
		}
	case int32:
		if v > 0 && v < 65535 {
			return true
		}
	}

	return false
}

func isTransport(in any) bool {
	if s, ok := in.(string); ok {
		for _, t := range validTransports {
			if strings.EqualFold(s, t) {
				return true
			}
		}
	}

	return false
}

func DashIfEmpty(value interface{}) string {
	switch v := value.(type) {
	case time.Time:
		if v.IsZero() || v == time.Date(0o001, time.January, 1, 0, 0, 0, 0, time.UTC) {
			return "-"
		}

		return v.Format(time.DateTime)
	case string:
		trimmed := strings.TrimSpace(v)
		if len(trimmed) == 0 {
			return "-"
		}

		return v
	case *string:
		if v == nil || len(strings.TrimSpace(*v)) == 0 {
			return "-"
		}

		return *v
	case int:
		return fmt.Sprintf("%d", v)
	default:
		return "-"
	}
}

type ProviderClient interface {
	Enabled() bool
	GetConfig() *session.Session
	Initialise() error
	FindHost() ([]byte, error)
	CreateTable([]byte) (*table.Writer, error)
}
