package ui

import (
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/jonhadfield/ipscout/providers/abuseipdb"
	"github.com/jonhadfield/ipscout/providers/bingbot"
	"github.com/jonhadfield/ipscout/providers/icloudpr"
	"github.com/jonhadfield/ipscout/providers/linode"
	"github.com/jonhadfield/ipscout/providers/ovh"
	"github.com/jonhadfield/ipscout/providers/zscaler"

	"github.com/jonhadfield/ipscout/providers/annotated"

	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/providers/aws"
	"github.com/jonhadfield/ipscout/providers/googlebot"
	"github.com/jonhadfield/ipscout/providers/hetzner"
	"github.com/jonhadfield/ipscout/providers/ipapi"
	"github.com/jonhadfield/ipscout/providers/ipqs"
	"github.com/jonhadfield/ipscout/providers/ipurl"
	"github.com/jonhadfield/ipscout/providers/virustotal"

	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers/criminalip"
	"github.com/jonhadfield/ipscout/providers/shodan"
	"github.com/jonhadfield/ipscout/session"
)

type Provider struct {
	Name      string
	Enabled   *bool
	APIKey    string
	NewClient func(c session.Session) (providers.ProviderClient, error)
}

func getProviderClient(sess *session.Session, providerName string) (providers.ProviderClient, error) {
	if sess == nil {
		return nil, fmt.Errorf("getProviderClient: session is nil")
	}

	var pc providers.ProviderClient

	var err error

	switch providerName {
	case abuseipdb.ProviderName:
		if *sess.Providers.AbuseIPDB.Enabled {
			pc, err = abuseipdb.NewClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create AbuseIPDB client: %w", err)
			}
		}
	case annotated.ProviderName:
		if *sess.Providers.Annotated.Enabled {
			pc, err = annotated.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create annotated client: %w", err)
			}
		}
	case aws.ProviderName:
		if *sess.Providers.AWS.Enabled {
			pc, err = aws.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create AWS client: %w", err)
			}
		}
	case bingbot.ProviderName:
		if sess.Providers.Bingbot.Enabled == nil {
			return nil, fmt.Errorf("getProviderClient: bingbot provider enabled is nil")
		}

		if *sess.Providers.Bingbot.Enabled {
			pc, err = bingbot.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create bingbot client: %w", err)
			}
		}

	case ipapi.ProviderName:
		if sess.Providers.IPAPI.Enabled == nil {
			return nil, fmt.Errorf("getProviderClient: ipapi provider enabled is nil")
		}

		if *sess.Providers.IPAPI.Enabled {
			pc, err = ipapi.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create IPAPI client: %w", err)
			}
		}
	case ipurl.ProviderName:
		if *sess.Providers.IPURL.Enabled {
			pc, err = ipurl.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create IPURL client: %w", err)
			}
		}
	case googlebot.ProviderName:
		if *sess.Providers.Googlebot.Enabled {
			pc, err = googlebot.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create Googlebot client: %w", err)
			}
		}
	case hetzner.ProviderName:
		if *sess.Providers.Hetzner.Enabled {
			pc, err = hetzner.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create Hetzner client: %w", err)
			}
		}
	case icloudpr.ProviderName:
		if *sess.Providers.ICloudPR.Enabled {
			pc, err = icloudpr.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create ICloudPR client: %w", err)
			}
		}
	case ipqs.ProviderName:
		if *sess.Providers.IPQS.Enabled {
			pc, err = ipqs.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create IPQS client: %w", err)
			}
		}
	case linode.ProviderName:
		if *sess.Providers.Linode.Enabled {
			pc, err = linode.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create Linode client: %w", err)
			}
		}
	case ovh.ProviderName:
		if *sess.Providers.OVH.Enabled {
			pc, err = ovh.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create OVH client: %w", err)
			}
		}
	case shodan.ProviderName:
		if sess.Providers.Shodan.Enabled == nil {
			return nil, fmt.Errorf("getProviderClient: Shodan provider enabled is nil")
		}

		if *sess.Providers.Shodan.Enabled {
			pc, err = shodan.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create Shodan client: %w", err)
			}
		}
	case virustotal.ProviderName:
		if *sess.Providers.VirusTotal.Enabled {
			pc, err = virustotal.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create VirusTotal client: %w", err)
			}
		}
	case zscaler.ProviderName:
		if *sess.Providers.Zscaler.Enabled {
			pc, err = zscaler.NewProviderClient(*sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create ZScaler client: %w", err)
			}
		}
	}

	if pc != nil && !pc.Enabled() {
		return nil, fmt.Errorf("provider %s is not enabled", providerName)
	}

	if pc == nil {
		return nil, fmt.Errorf("provider %s is not supported", providerName)
	}

	if pc.GetConfig().Host == (netip.Addr{}) {
		return nil, fmt.Errorf("provider %s has no host configured", providerName)
	}

	return pc, nil
}

type Config struct {
	session.Session
	Shodan     shodan.Config
	CriminalIP criminalip.Config
	IPURL      ipurl.Config
}

type Processor struct {
	Session *session.Session
}

// func fetchShodan(sess *session.Session) (findHostsResults, error) {
// 	initialiseProviders(p.Session.Logger, enabledProviders, p.Session.HideProgress)
// }

func (p *Processor) Run(providerName string) (string, error) {
	db, err := cache.Create(p.Session.Logger, filepath.Join(p.Session.Config.Global.HomeDir, ".config", "ipscout"))
	if err != nil {
		return "", fmt.Errorf("failed to create cache: %w", err)
	}

	p.Session.Cache = db

	defer db.Close()

	// get provider clients
	providerClient, err := getProviderClient(p.Session, providerName)
	if err != nil {
		_ = db.Close()

		return "", fmt.Errorf("failed to generate provider clients: %w", err)
	}

	// initialise providers
	slog.Info("initialising provider", "provider", providerName)
	initialiseProvider(p.Session.Logger, providerClient)
	slog.Info("finished initialising provider", "provider", providerName)

	if strings.EqualFold(p.Session.Config.Global.LogLevel, "debug") {
		for provider, dur := range p.Session.Stats.InitialiseDuration {
			p.Session.Logger.Debug("initialise timing", "provider", provider, "duration", dur.String())
		}
	}

	if p.Session.Config.Global.InitialiseCacheOnly {
		fmt.Fprintln(p.Session.Target, "cache initialisation complete")

		return "", nil
	}

	slog.Info("finding hosts", "provider", providerName)

	// find hosts
	result, err := findHosts(providerClient)
	if err != nil {
		return "", fmt.Errorf("failed to find hosts: %w", err)
	}

	if strings.EqualFold(p.Session.Config.Global.LogLevel, "debug") {
		for provider, dur := range p.Session.Stats.FindHostDuration {
			p.Session.Logger.Debug("find hosts timing", "provider", provider, "duration", dur.String())
		}

		for provider, uc := range p.Session.Stats.FindHostUsedCache {
			p.Session.Logger.Debug("find hosts data load", "provider", provider, "cache", uc)
		}
	}

	// p.Session.Logger.Info("host matching result", "providers queried", len(enabledProviders), "matching result", matchingResults)
	//
	// if matchingResults == 0 {
	// 	p.Session.Logger.Warn("no result found", "host", p.Session.Host.String(), "providers checked", strings.Join(mapsKeys(enabledProviders), ", "))
	//
	// 	return nil
	// }

	// output data
	// if err = output(p.Session, providerClient, result); err != nil {
	// 	return fmt.Errorf("failed to output data: %w", err)
	// }

	return string(result), nil
}

func initialiseProvider(l *slog.Logger, runner providers.ProviderClient) {
	if !runner.Enabled() {
		return
	}

	l.Debug("initialising provider")

	err := runner.Initialise()
	if err != nil {
		l.Error("failed to initialise", "error", err.Error())
	}
}

func findHosts(runner providers.ProviderClient) ([]byte, error) {
	var result []byte

	result, err := runner.FindHost()
	if err != nil {
		runner.GetConfig().Logger.Info(err.Error())

		return nil, fmt.Errorf("failed to find hosts: %w", err)
	}

	return result, nil
}

func New(sess *session.Session) Processor {
	p := Processor{
		Session: sess,
	}

	return p
}
