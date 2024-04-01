package providers

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPortMatch(t *testing.T) {
	ports := []string{"80", "tcp", "80/tcp"}
	require.True(t, PortMatch("80", []string{}))
	require.True(t, PortMatch("80", ports))
	require.False(t, PortMatch("800", ports))
	require.True(t, PortMatch("tcp", ports))
	require.False(t, PortMatch("udp", ports))
	require.True(t, PortMatch("80/tcp", ports))
	require.True(t, PortMatch("80/udp", ports))
}

func TestPortMatchNonWideTransport(t *testing.T) {
	ports := []string{"80", "80/tcp"}
	require.False(t, PortMatch("50/tcp", ports))
	require.True(t, PortMatch("80", []string{}))
	require.True(t, PortMatch("80", ports))
	require.False(t, PortMatch("800", ports))
	require.True(t, PortMatch("tcp", ports))
	require.False(t, PortMatch("udp", ports))
	require.True(t, PortMatch("80/tcp", ports))
	require.True(t, PortMatch("80/udp", ports))
}

func TestPortMatchNonWidePort(t *testing.T) {
	ports := []string{"tcp", "80/tcp"}
	require.True(t, PortMatch("50/tcp", ports))
	require.True(t, PortMatch("80", []string{}))
	require.True(t, PortMatch("80", ports))
	require.False(t, PortMatch("800", ports))
	require.True(t, PortMatch("tcp", ports))
	require.False(t, PortMatch("udp", ports))
	require.True(t, PortMatch("80/tcp", ports))
	require.False(t, PortMatch("80/udp", ports))
}

func TestSplitPortTransport(t *testing.T) {
	pt := splitPortTransport("80")
	require.Equal(t, "80", pt.port)
	require.Empty(t, pt.transport)

	pt = splitPortTransport("tcp")
	require.Empty(t, pt.port)
	require.Equal(t, "tcp", pt.transport)

	pt = splitPortTransport("80/tcp")
	require.Equal(t, "80", pt.port)
	require.Equal(t, "tcp", pt.transport)

	pt = splitPortTransport("80/udp")
	require.Equal(t, "80", pt.port)
	require.Equal(t, "udp", pt.transport)
}

func TestIsPort(t *testing.T) {
	require.True(t, isPort("80"))
	require.True(t, isPort("800"))
	require.False(t, isPort("80000"))
	require.False(t, isPort("tcp"))
}
