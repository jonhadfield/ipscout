package providers

import (
	"errors"
	"fmt"
	"github.com/jonhadfield/crosscheck-ip/config"
	"strconv"
	"strings"
)

var (
	ErrFailedToFetchData = errors.New("failed to fetch data")
	ErrNoDataFound       = errors.New("no data found")
	ErrNoMatchFound      = errors.New("no match found")
)

// PortMatch returns true if either:
// - specified port matches the data port
// - specified transport matches the data transport
// - specified port/transport matches the data port/transport
func PortMatch(incomingPort string, matchPorts []string) bool {
	if len(matchPorts) == 0 {
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
