package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

const (
	retryWaitMin = 3 * time.Second
	retryWaitMax = 5 * time.Second
	retryMax     = 3
)

func getHTTPClient() *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.RetryWaitMin = retryWaitMin
	hc.RetryWaitMax = retryWaitMax
	hc.RetryMax = retryMax
	hc.Logger = nil

	return hc
}

// parseHost attempts to convert the provided argument into a netip.Addr. If the
// argument isn't already an IP address, it is treated as a hostname and
// resolved using the system resolver.
func parseHost(arg string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(arg); err == nil {
		return addr, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", arg)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to resolve host: %w", err)
	}

	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("no ip addresses found for %s", arg)
	}

	addr, err := netip.ParseAddr(ips[0].String())
	if err != nil {
		return netip.Addr{}, err
	}

	return addr, nil
}
