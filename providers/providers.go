package providers

import (
	"errors"
	"strconv"
	"strings"
)

var (
	ErrNoDataFound         = errors.New("no data found")
	ErrDataProviderFailure = errors.New("data provider failure")
)

// PortMatch returns true if either:
// - specified port matches the data port
// - specified transport matches the data transport
// - specified port/transport matches the data port/transport
func PortMatch(port string, matchPorts []string) bool {
	if len(matchPorts) == 0 {
		return true
	}

	for _, p := range matchPorts {
		splitMatch := splitPortTransport(p)
		splitPort := splitPortTransport(port)

		// most specific first
		switch {
		case splitMatch.port == splitPort.port && splitMatch.transport == splitPort.transport:
			// if both parts of match port are set, then only a full match will do
			return true
		case splitMatch.port != "" && splitMatch.port == splitPort.port:
			// if only port is set, then only port needs to match
			return true
		case splitMatch.transport != "" && splitMatch.transport == splitPort.transport:
			// if only transport is set, then only transport needs to match
			return true
		}
	}

	return false
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
