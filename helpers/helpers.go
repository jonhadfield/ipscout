package helpers

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	c "github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/session"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var (
	Version string
	SemVer  string
)

// ParseHost attempts to convert the provided argument into a netip.Addr. If the
// argument isn't already an IP address, it is treated as a hostname and
// resolved using the system resolver.
func ParseHost(arg string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(arg); err == nil {
		return addr, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.NameLookupDelay)
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
		return netip.Addr{}, fmt.Errorf("failed to parse resolved IP address: %w", err)
	}

	return addr, nil
}

func GetHTTPClient() *retryablehttp.Client {
	hc := retryablehttp.NewClient()
	hc.RetryWaitMin = c.RetryWaitMin
	hc.RetryWaitMax = c.RetryWaitMax
	hc.RetryMax = c.RetryMax
	hc.Logger = nil

	return hc
}

func InitHomeDirConfig(sess *session.Session, v *viper.Viper) error {
	var err error

	homeDir := v.GetString("home_dir")
	if homeDir == "" {
		homeDir, err = homedir.Dir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
	}

	// check home directory exists
	_, err = os.Stat(homeDir)
	if err != nil && os.IsNotExist(err) {
		return fmt.Errorf("home directory %s does not exist: %w", homeDir, err)
	}

	sess.Config.Global.HomeDir = homeDir

	return nil
}

// TrackDuration returns a closure that records the duration since it was created
// in the supplied map using provider as the key. It is designed for use with
// defer when timing operations.
func TrackDuration(mu *sync.Mutex, m map[string]time.Duration, provider string) func() {
	start := time.Now()

	return func() {
		mu.Lock()
		m[provider] = time.Since(start)
		mu.Unlock()
	}
}
