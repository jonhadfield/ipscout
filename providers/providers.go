package providers

import (
	"errors"
	"fmt"
	"github.com/jonhadfield/crosscheck-ip/config"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

var (
	ErrFailedToFetchData = errors.New("failed to fetch data")
	ErrNoDataFound       = errors.New("no data found")
	ErrNoMatchFound      = errors.New("no match found")
)

func AgeToHours(age string) (int64, error) {
	if age == "" {
		return 0, nil
	}

	age = strings.ToLower(age)

	// assume hours specified
	var multipler int

	switch {
	case strings.HasSuffix(age, "h"):
		age = strings.TrimSuffix(age, "h")
		multipler = 1
	case strings.HasSuffix(age, "d"):
		age = strings.TrimSuffix(age, "d")
		multipler = 24
	case strings.HasSuffix(age, "w"):
		age = strings.TrimSuffix(age, "w")
		multipler = 24 * 7
	case strings.HasSuffix(age, "m"):
		age = strings.TrimSuffix(age, "m")
		multipler = 24 * 30
	case strings.HasSuffix(age, "y"):
		age = strings.TrimSuffix(age, "m")
		multipler = 24 * 365
	default:

	}

	var ageNum int64
	ageNum, err := strconv.ParseInt(age, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("error parsing age: %w", err)
	}

	return ageNum * int64(multipler), nil
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
		return false, err
	}

	if confirmedTime.After(time.Now().Add(-time.Duration(maxAgeHours) * time.Hour)) {
		return true, err
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

// PortMatchFilter returns true if the incoming port matches the matchPorts and the port is within the max age
func PortMatchFilter(in PortMatchFilterInput) (ageMatch, netMatch bool, err error) {
	if len(in.IncomingPort) == 0 && len(in.MaxAge) == 0 {
		return false, false, errors.New("no incoming port nor max age provided")
	}

	netMatch = PortNetworkMatch(in.IncomingPort, in.MatchPorts)

	ageMatch, err = portAgeCheck(in.ConfirmedDate, in.ConfirmedDateFormat, in.MaxAge)
	if err != nil {
		return ageMatch, false, fmt.Errorf("error checking port age: %w", err)
	}

	// default to true as no filter matched
	return ageMatch, netMatch, nil
}

// TODO: Allow provider specific max value chars to override global
func PreProcessValueOutput(conf *config.Config, provider string, in string) string {
	out := strings.TrimSpace(in)
	if conf.Global.MaxValueChars > 0 {
		if len(out) > int(conf.Global.MaxValueChars) {
			out = out[:conf.Global.MaxValueChars] + "..."
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
	case string:
		if len(v) == 0 {
			return "-"
		}
		return v
	case *string:
		if v == nil || len(*v) == 0 {
			return "-"
		}
		return *v
	case int:
		return fmt.Sprintf("%d", v)
	default:
		return "-"
	}
}
