package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/jonhadfield/ipscout/session"
)

const (
	DefaultUA          = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125."
	TimeFormat         = "2006-01-02 15:04:05 MST"
	Column1MinWidth    = 14
	WideColumnMaxWidth = 75
	WideColumnMinWidth = 50
)

func RowEmphasisColor(sess session.Session) func(format string, a ...interface{}) string {
	switch sess.Config.Global.Style {
	case "ascii":
		return fmt.Sprintf
	case "yellow":
		return color.YellowString
	case "red":
		return color.RedString
	case "green":
		return color.GreenString
	case "blue":
		return color.BlueString
	case "cyan":
		return color.CyanString
	default:
		return color.CyanString
	}
}

var (
	ErrFailedToFetchData   = errors.New("failed to fetch data")
	ErrNoDataFound         = errors.New("no data found")
	ErrNoMatchFound        = errors.New("no match found")
	ErrForbiddenByProvider = errors.New("forbidden by provider")
	CacheProviderPrefix    = "provider_"
	CacheKeySHALen         = 15
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

		return v.Format(TimeFormat)
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

type TableWithPriority struct {
	Table    *table.Writer
	Priority *int32
}

type ProviderClient interface {
	Enabled() bool
	GetConfig() *session.Session
	Initialise() error
	FindHost() ([]byte, error)
	CreateTable([]byte) (*table.Writer, error)
	Priority() *int32
	RateHostData([]byte, []byte) (RateResult, error)
}

type RateResult struct {
	// Provider string
	Detected bool
	Score    float64
	Reasons  []string
	Threat   string
}

func FormatTimeOrDash(s string, format string) string {
	if s == "" || format == "" {
		return "-"
	}

	result, err := time.Parse(format, s)
	if err != nil {
		return "-"
	}

	if result.IsZero() {
		return "-"
	}

	return result.UTC().Format(TimeFormat)
}

func PadRight(str string, length int) string {
	return str + strings.Repeat(" ", length-len(str))
}

// TODO: allow user specified rating config
func LoadRatingConfig(ratingConfigJSON string) (*RatingConfig, error) {
	ratingConfig := RatingConfig{}
	if err := json.Unmarshal([]byte(ratingConfigJSON), &ratingConfig); err != nil {
		return nil, fmt.Errorf("error unmarshalling default rating config: %w", err)
	}

	return &ratingConfig, nil
}

type RatingConfig struct {
	Global struct {
		HighThreatCountryCodes   []string `json:"highThreatCountryCodes"`
		MediumThreatCountryCodes []string `json:"mediumThreatCountryCodes"`
	}
	ProviderRatingsConfigs struct {
		IPURL struct {
			Hello             string  `json:"hello,omitempty"`
			DefaultMatchScore float64 `json:"defaultMatchScore,omitempty"`
		} `json:"ipurl"`
	} `json:"providers"`
}

type ProviderRatingConfig struct {
	DefaultMatchScore float64 `json:"defaultMatchScore"`
}
