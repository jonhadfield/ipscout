package registry

import (
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/providers/abuseipdb"
	"github.com/jonhadfield/ipscout/providers/alibaba"
	"github.com/jonhadfield/ipscout/providers/annotated"
	"github.com/jonhadfield/ipscout/providers/aws"
	"github.com/jonhadfield/ipscout/providers/azure"
	"github.com/jonhadfield/ipscout/providers/azurewaf"
	"github.com/jonhadfield/ipscout/providers/bingbot"
	"github.com/jonhadfield/ipscout/providers/criminalip"
	"github.com/jonhadfield/ipscout/providers/digitalocean"
	"github.com/jonhadfield/ipscout/providers/gcp"
	"github.com/jonhadfield/ipscout/providers/google"
	"github.com/jonhadfield/ipscout/providers/googlebot"
	"github.com/jonhadfield/ipscout/providers/googlesc"
	"github.com/jonhadfield/ipscout/providers/hetzner"
	"github.com/jonhadfield/ipscout/providers/icloudpr"
	"github.com/jonhadfield/ipscout/providers/ipapi"
	"github.com/jonhadfield/ipscout/providers/ipqs"
	"github.com/jonhadfield/ipscout/providers/ipurl"
	"github.com/jonhadfield/ipscout/providers/linode"
	"github.com/jonhadfield/ipscout/providers/m247"
	"github.com/jonhadfield/ipscout/providers/ovh"
	"github.com/jonhadfield/ipscout/providers/ptr"
	"github.com/jonhadfield/ipscout/providers/scaleway"
	"github.com/jonhadfield/ipscout/providers/shodan"
	"github.com/jonhadfield/ipscout/providers/virustotal"
	"github.com/jonhadfield/ipscout/providers/vultr"
	"github.com/jonhadfield/ipscout/providers/zscaler"
	"github.com/jonhadfield/ipscout/session"
)

// Entry describes a provider and how to instantiate it.
type Entry struct {
	Name           string
	Enabled        func(sess session.Session) *bool
	APIKey         func(sess session.Session) string
	NewClient      func(sess session.Session) (providers.ProviderClient, error)
	SupportsRating bool
}

// All returns the full list of known provider registrations.
// This is the single source of truth — process and rate both call this.
func All() []Entry {
	return []Entry{
		{Name: abuseipdb.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.AbuseIPDB.Enabled }, APIKey: func(s session.Session) string { return s.Providers.AbuseIPDB.APIKey }, NewClient: abuseipdb.NewClient, SupportsRating: true},
		{Name: alibaba.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.Alibaba.Enabled }, APIKey: noKey, NewClient: alibaba.NewProviderClient, SupportsRating: false},
		{Name: annotated.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.Annotated.Enabled }, APIKey: noKey, NewClient: annotated.NewProviderClient, SupportsRating: true},
		{Name: aws.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.AWS.Enabled }, APIKey: noKey, NewClient: aws.NewProviderClient, SupportsRating: true},
		{Name: azure.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.Azure.Enabled }, APIKey: noKey, NewClient: azure.NewProviderClient, SupportsRating: true},
		{Name: azurewaf.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.AzureWAF.Enabled }, APIKey: noKey, NewClient: azurewaf.NewProviderClient, SupportsRating: false},
		{Name: bingbot.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.Bingbot.Enabled }, APIKey: noKey, NewClient: bingbot.NewProviderClient, SupportsRating: true},
		{Name: criminalip.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.CriminalIP.Enabled }, APIKey: func(s session.Session) string { return s.Providers.CriminalIP.APIKey }, NewClient: criminalip.NewProviderClient, SupportsRating: true},
		{Name: digitalocean.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.DigitalOcean.Enabled }, APIKey: noKey, NewClient: digitalocean.NewProviderClient, SupportsRating: true},
		{Name: gcp.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.GCP.Enabled }, APIKey: noKey, NewClient: gcp.NewProviderClient, SupportsRating: true},
		{Name: google.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.Google.Enabled }, APIKey: noKey, NewClient: google.NewProviderClient, SupportsRating: true},
		{Name: googlebot.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.Googlebot.Enabled }, APIKey: noKey, NewClient: googlebot.NewProviderClient, SupportsRating: true},
		{Name: googlesc.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.GoogleSC.Enabled }, APIKey: noKey, NewClient: googlesc.NewProviderClient, SupportsRating: false},
		{Name: hetzner.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.Hetzner.Enabled }, APIKey: noKey, NewClient: hetzner.NewProviderClient, SupportsRating: true},
		{Name: ipapi.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.IPAPI.Enabled }, APIKey: noKey, NewClient: ipapi.NewProviderClient, SupportsRating: true},
		{Name: ipqs.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.IPQS.Enabled }, APIKey: func(s session.Session) string { return s.Providers.IPQS.APIKey }, NewClient: ipqs.NewProviderClient, SupportsRating: true},
		{Name: ipurl.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.IPURL.Enabled }, APIKey: noKey, NewClient: ipurl.NewProviderClient, SupportsRating: true},
		{Name: icloudpr.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.ICloudPR.Enabled }, APIKey: noKey, NewClient: icloudpr.NewProviderClient, SupportsRating: true},
		{Name: linode.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.Linode.Enabled }, APIKey: noKey, NewClient: linode.NewProviderClient, SupportsRating: true},
		{Name: m247.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.M247.Enabled }, APIKey: noKey, NewClient: m247.NewProviderClient, SupportsRating: false},
		{Name: ovh.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.OVH.Enabled }, APIKey: noKey, NewClient: ovh.NewProviderClient, SupportsRating: true},
		{Name: scaleway.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.Scaleway.Enabled }, APIKey: noKey, NewClient: scaleway.NewProviderClient, SupportsRating: false},
		{Name: ptr.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.PTR.Enabled }, APIKey: noKey, NewClient: ptr.NewProviderClient, SupportsRating: false},
		{Name: shodan.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.Shodan.Enabled }, APIKey: func(s session.Session) string { return s.Providers.Shodan.APIKey }, NewClient: shodan.NewProviderClient, SupportsRating: true},
		{Name: virustotal.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.VirusTotal.Enabled }, APIKey: func(s session.Session) string { return s.Providers.VirusTotal.APIKey }, NewClient: virustotal.NewProviderClient, SupportsRating: true},
		{Name: vultr.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.Vultr.Enabled }, APIKey: noKey, NewClient: vultr.NewProviderClient, SupportsRating: false},
		{Name: zscaler.ProviderName, Enabled: func(s session.Session) *bool { return s.Providers.Zscaler.Enabled }, APIKey: noKey, NewClient: zscaler.NewProviderClient, SupportsRating: true},
	}
}

func noKey(_ session.Session) string { return "" }
