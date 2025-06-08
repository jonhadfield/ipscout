package cmd

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseHost(t *testing.T) {
	t.Run("ip", func(t *testing.T) {
		addr, err := parseHost("1.1.1.1")
		require.NoError(t, err)
		require.Equal(t, netip.MustParseAddr("1.1.1.1"), addr)
	})

	t.Run("fqdn", func(t *testing.T) {
		addr, err := parseHost("localhost")
		require.NoError(t, err)
		require.True(t, addr.IsLoopback())
	})
}
