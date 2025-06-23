package ui

import (
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/jonhadfield/ipscout/providers/annotated"

	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/providers/ipapi"
	"github.com/jonhadfield/ipscout/providers/ipurl"

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

func getProviderClient(sess session.Session, providerName string) (providers.ProviderClient, error) {
	var pc providers.ProviderClient

	var err error

	switch providerName {
	case annotated.ProviderName:
		if *sess.Providers.Annotated.Enabled {
			pc, err = annotated.NewProviderClient(sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create aQnnotated client: %w", err)
			}
		}
	case shodan.ProviderName:
		if *sess.Providers.Shodan.Enabled {
			pc, err = shodan.NewProviderClient(sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create Shodan client: %w", err)
			}
		}
	case ipapi.ProviderName:
		if *sess.Providers.IPAPI.Enabled {
			pc, err = ipapi.NewProviderClient(sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create IPAPI client: %w", err)
			}
		}
	case ipurl.ProviderName:
		if *sess.Providers.IPURL.Enabled {
			pc, err = ipurl.NewProviderClient(sess)
			if err != nil {
				return nil, fmt.Errorf("failed to create IPURL client: %w", err)
			}
		}
		// {Name: abuseipdb.ProviderName, Enabled: sess.Providers.AbuseIPDB.Enabled, APIKey: sess.Providers.AbuseIPDB.APIKey, NewClient: abuseipdb.NewClient},
		// {Name: annotated.ProviderName, Enabled: sess.Providers.Annotated.Enabled, APIKey: "", NewClient: annotated.NewProviderClient},
		// {Name: aws.ProviderName, Enabled: sess.Providers.AWS.Enabled, APIKey: "", NewClient: aws.NewProviderClient},
		// {Name: azure.ProviderName, Enabled: sess.Providers.Azure.Enabled, APIKey: "", NewClient: azure.NewProviderClient},
		// {Name: azurewaf.ProviderName, Enabled: sess.Providers.AzureWAF.Enabled, APIKey: "", NewClient: azurewaf.NewProviderClient},
		// {Name: bingbot.ProviderName, Enabled: sess.Providers.Bingbot.Enabled, APIKey: "", NewClient: bingbot.NewProviderClient},
		// {Name: criminalip.ProviderName, Enabled: sess.Providers.CriminalIP.Enabled, APIKey: sess.Providers.CriminalIP.APIKey, NewClient: criminalip.NewProviderClient},
		// {Name: digitalocean.ProviderName, Enabled: sess.Providers.DigitalOcean.Enabled, APIKey: "", NewClient: digitalocean.NewProviderClient},
		// {Name: gcp.ProviderName, Enabled: sess.Providers.GCP.Enabled, APIKey: "", NewClient: gcp.NewProviderClient},
		// {Name: google.ProviderName, Enabled: sess.Providers.Google.Enabled, APIKey: "", NewClient: google.NewProviderClient},
		// {Name: googlebot.ProviderName, Enabled: sess.Providers.Googlebot.Enabled, APIKey: "", NewClient: googlebot.NewProviderClient},
		// {Name: googlesc.ProviderName, Enabled: sess.Providers.GoogleSC.Enabled, APIKey: "", NewClient: googlesc.NewProviderClient},
		// {Name: hetzner.ProviderName, Enabled: sess.Providers.Hetzner.Enabled, APIKey: "", NewClient: hetzner.NewProviderClient},
		// {Name: ipapi.ProviderName, Enabled: sess.Providers.IPAPI.Enabled, APIKey: "", NewClient: ipapi.NewProviderClient},
		// {Name: ipqs.ProviderName, Enabled: sess.Providers.IPQS.Enabled, APIKey: sess.Providers.IPQS.APIKey, NewClient: ipqs.NewProviderClient},
		// {Name: ipurl.ProviderName, Enabled: sess.Providers.IPURL.Enabled, APIKey: "", NewClient: ipurl.NewProviderClient},
		// {Name: icloudpr.ProviderName, Enabled: sess.Providers.ICloudPR.Enabled, APIKey: "", NewClient: icloudpr.NewProviderClient},
		// {Name: linode.ProviderName, Enabled: sess.Providers.Linode.Enabled, APIKey: "", NewClient: linode.NewProviderClient},
		// {Name: ovh.ProviderName, Enabled: sess.Providers.OVH.Enabled, APIKey: "", NewClient: ovh.NewProviderClient},
		// {Name: ptr.ProviderName, Enabled: sess.Providers.PTR.Enabled, APIKey: "", NewClient: ptr.NewProviderClient},
		// {Name: shodan.ProviderName, Enabled: sess.Providers.Shodan.Enabled, APIKey: sess.Providers.Shodan.APIKey, NewClient: shodan.NewProviderClient},
		// {Name: virustotal.ProviderName, Enabled: sess.Providers.VirusTotal.Enabled, APIKey: sess.Providers.VirusTotal.APIKey, NewClient: virustotal.NewProviderClient},
		// {Name: zscaler.ProviderName, Enabled: sess.Providers.Zscaler.Enabled, APIKey: "", NewClient: zscaler.NewProviderClient},
		return pc, nil
	}

	if pc != nil && !pc.Enabled() {
		return nil, fmt.Errorf("provider %s is not enabled", providerName)
	}

	if pc.GetConfig().Host == (netip.Addr{}) {
		return nil, fmt.Errorf("providerAAAAA %s has no host configured", providerName)
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
	sess.Logger.Warn("debug", "sess", p.Session, " providerName", providerName)

	providerClient, err := getProviderClient(*p.Session, providerName)
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
