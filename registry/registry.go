package registry

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/providers/abuseipdb"
	"github.com/jonhadfield/ipscout/providers/ahrefs"
	"github.com/jonhadfield/ipscout/providers/akamai"
	"github.com/jonhadfield/ipscout/providers/alibaba"
	"github.com/jonhadfield/ipscout/providers/annotated"
	"github.com/jonhadfield/ipscout/providers/anthropic"
	"github.com/jonhadfield/ipscout/providers/applebot"
	"github.com/jonhadfield/ipscout/providers/atlassian"
	"github.com/jonhadfield/ipscout/providers/aws"
	"github.com/jonhadfield/ipscout/providers/azure"
	"github.com/jonhadfield/ipscout/providers/azurewaf"
	"github.com/jonhadfield/ipscout/providers/bingbot"
	"github.com/jonhadfield/ipscout/providers/blocklistde"
	"github.com/jonhadfield/ipscout/providers/bunny"
	"github.com/jonhadfield/ipscout/providers/cdn77"
	"github.com/jonhadfield/ipscout/providers/cinsscore"
	"github.com/jonhadfield/ipscout/providers/cloudflare"
	"github.com/jonhadfield/ipscout/providers/contabo"
	"github.com/jonhadfield/ipscout/providers/criminalip"
	"github.com/jonhadfield/ipscout/providers/cymru"
	"github.com/jonhadfield/ipscout/providers/datadog"
	"github.com/jonhadfield/ipscout/providers/digitalocean"
	"github.com/jonhadfield/ipscout/providers/dshield"
	"github.com/jonhadfield/ipscout/providers/duckduckbot"
	"github.com/jonhadfield/ipscout/providers/emergingthreats"
	"github.com/jonhadfield/ipscout/providers/fastly"
	"github.com/jonhadfield/ipscout/providers/flyio"
	"github.com/jonhadfield/ipscout/providers/gcp"
	"github.com/jonhadfield/ipscout/providers/github"
	"github.com/jonhadfield/ipscout/providers/google"
	"github.com/jonhadfield/ipscout/providers/googlebot"
	"github.com/jonhadfield/ipscout/providers/googlesc"
	"github.com/jonhadfield/ipscout/providers/googleutf"
	"github.com/jonhadfield/ipscout/providers/greensnow"
	"github.com/jonhadfield/ipscout/providers/hetzner"
	"github.com/jonhadfield/ipscout/providers/ibmcloud"
	"github.com/jonhadfield/ipscout/providers/icloudpr"
	"github.com/jonhadfield/ipscout/providers/imperva"
	"github.com/jonhadfield/ipscout/providers/ipapi"
	"github.com/jonhadfield/ipscout/providers/ipqs"
	"github.com/jonhadfield/ipscout/providers/iptoasn"
	"github.com/jonhadfield/ipscout/providers/ipurl"
	"github.com/jonhadfield/ipscout/providers/leaseweb"
	"github.com/jonhadfield/ipscout/providers/linode"
	"github.com/jonhadfield/ipscout/providers/m247"
	"github.com/jonhadfield/ipscout/providers/oci"
	"github.com/jonhadfield/ipscout/providers/openai"
	"github.com/jonhadfield/ipscout/providers/ovh"
	"github.com/jonhadfield/ipscout/providers/perplexitybot"
	"github.com/jonhadfield/ipscout/providers/ptr"
	"github.com/jonhadfield/ipscout/providers/render"
	"github.com/jonhadfield/ipscout/providers/scaleway"
	"github.com/jonhadfield/ipscout/providers/shodan"
	"github.com/jonhadfield/ipscout/providers/spamhaus"
	"github.com/jonhadfield/ipscout/providers/stripe"
	"github.com/jonhadfield/ipscout/providers/tencent"
	"github.com/jonhadfield/ipscout/providers/uptimerobot"
	"github.com/jonhadfield/ipscout/providers/virustotal"
	"github.com/jonhadfield/ipscout/providers/vultr"
	"github.com/jonhadfield/ipscout/providers/zscaler"
	"github.com/jonhadfield/ipscout/session"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// yamlIndent is the indentation used when rewriting the config file, matching
// the shipped default config.
const yamlIndent = 2

// Entry describes a provider and how to instantiate it.
type Entry struct {
	Name string
	// DisplayName is the human-friendly name shown in `ipscout config`.
	DisplayName    string
	Enabled        func(sess session.Session) *bool
	APIKey         func(sess session.Session) string
	NewClient      func(sess session.Session) (providers.ProviderClient, error)
	SupportsRating bool
	// DefaultEnabled marks providers that require no configuration (no API
	// key, paths, URLs or resource IDs) and are therefore enabled by default
	// when absent from the user's config file.
	DefaultEnabled bool
}

// EnsureDefaultProvidersInConfig adds an enabled=true entry to the config file
// at configPath for every no-config provider missing from its providers
// section, so existing users see newly added providers in their config as
// enabled. Comments and ordering of existing entries are preserved. It returns
// true if the file was updated.
func EnsureDefaultProvidersInConfig(configPath string) (bool, error) {
	info, err := os.Stat(configPath)
	if err != nil {
		return false, fmt.Errorf("failed to stat config file: %w", err)
	}

	data, err := os.ReadFile(configPath) // #nosec G304 -- path is the app's own config file
	if err != nil {
		return false, fmt.Errorf("failed to read config file: %w", err)
	}

	var doc yaml.Node
	if err = yaml.Unmarshal(data, &doc); err != nil {
		return false, fmt.Errorf("failed to parse config file: %w", err)
	}

	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return false, nil
	}

	root := doc.Content[0]

	var providersNode *yaml.Node

	for i := 0; i < len(root.Content)-1; i += 2 {
		if root.Content[i].Value == "providers" {
			providersNode = root.Content[i+1]

			break
		}
	}

	if providersNode == nil {
		providersNode = &yaml.Node{Kind: yaml.MappingNode}
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "providers"},
			providersNode)
	}

	// an empty providers section parses as a null scalar
	if providersNode.Kind != yaml.MappingNode {
		providersNode.Kind = yaml.MappingNode
		providersNode.Tag = ""
		providersNode.Value = ""
		providersNode.Content = nil
	}

	existing := make(map[string]bool)
	for i := 0; i < len(providersNode.Content)-1; i += 2 {
		existing[strings.ToLower(providersNode.Content[i].Value)] = true
	}

	var changed bool

	for _, e := range All() {
		// config keys are lowercase by convention; some ProviderName
		// constants (e.g. M247) are not
		name := strings.ToLower(e.Name)
		if !e.DefaultEnabled || existing[name] {
			continue
		}

		providersNode.Content = append(providersNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: name},
			&yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "enabled"},
				{Kind: yaml.ScalarNode, Value: "true"},
			}})

		changed = true
	}

	if !changed {
		return false, nil
	}

	var buf bytes.Buffer

	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(yamlIndent)

	if err = enc.Encode(&doc); err != nil {
		return false, fmt.Errorf("failed to encode config file: %w", err)
	}

	if err = enc.Close(); err != nil {
		return false, fmt.Errorf("failed to encode config file: %w", err)
	}

	if err = os.WriteFile(configPath, buf.Bytes(), info.Mode().Perm()); err != nil {
		return false, fmt.Errorf("failed to write config file: %w", err)
	}

	return true, nil
}

// SetEnabledDefaults registers an enabled=true default for every provider that
// requires no configuration, so providers added after a user's config file was
// written are still enabled rather than silently skipped. Explicit config
// values always take precedence over these defaults.
func SetEnabledDefaults(v *viper.Viper) {
	for _, e := range All() {
		if e.DefaultEnabled {
			v.SetDefault("providers."+strings.ToLower(e.Name)+".enabled", true)
		}
	}
}

// All returns the full list of known provider registrations.
// This is the single source of truth — process and rate both call this.
func All() []Entry {
	return []Entry{
		{Name: abuseipdb.ProviderName, DisplayName: "AbuseIPDB", Enabled: func(s session.Session) *bool { return s.Providers.AbuseIPDB.Enabled }, APIKey: func(s session.Session) string { return s.Providers.AbuseIPDB.APIKey }, NewClient: abuseipdb.NewClient, SupportsRating: true},
		{Name: alibaba.ProviderName, DisplayName: "Alibaba", Enabled: func(s session.Session) *bool { return s.Providers.Alibaba.Enabled }, APIKey: noKey, NewClient: alibaba.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: annotated.ProviderName, DisplayName: "Annotated", Enabled: func(s session.Session) *bool { return s.Providers.Annotated.Enabled }, APIKey: noKey, NewClient: annotated.NewProviderClient, SupportsRating: true},
		{Name: aws.ProviderName, DisplayName: "AWS", Enabled: func(s session.Session) *bool { return s.Providers.AWS.Enabled }, APIKey: noKey, NewClient: aws.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: azure.ProviderName, DisplayName: "Azure", Enabled: func(s session.Session) *bool { return s.Providers.Azure.Enabled }, APIKey: noKey, NewClient: azure.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: azurewaf.ProviderName, DisplayName: "Azure WAF", Enabled: func(s session.Session) *bool { return s.Providers.AzureWAF.Enabled }, APIKey: noKey, NewClient: azurewaf.NewProviderClient, SupportsRating: false},
		{Name: bingbot.ProviderName, DisplayName: "Bingbot", Enabled: func(s session.Session) *bool { return s.Providers.Bingbot.Enabled }, APIKey: noKey, NewClient: bingbot.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: criminalip.ProviderName, DisplayName: "CriminalIP", Enabled: func(s session.Session) *bool { return s.Providers.CriminalIP.Enabled }, APIKey: func(s session.Session) string { return s.Providers.CriminalIP.APIKey }, NewClient: criminalip.NewProviderClient, SupportsRating: true},
		{Name: digitalocean.ProviderName, DisplayName: "DigitalOcean", Enabled: func(s session.Session) *bool { return s.Providers.DigitalOcean.Enabled }, APIKey: noKey, NewClient: digitalocean.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: gcp.ProviderName, DisplayName: "GCP", Enabled: func(s session.Session) *bool { return s.Providers.GCP.Enabled }, APIKey: noKey, NewClient: gcp.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: google.ProviderName, DisplayName: "Google", Enabled: func(s session.Session) *bool { return s.Providers.Google.Enabled }, APIKey: noKey, NewClient: google.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: googlebot.ProviderName, DisplayName: "Googlebot", Enabled: func(s session.Session) *bool { return s.Providers.Googlebot.Enabled }, APIKey: noKey, NewClient: googlebot.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: googlesc.ProviderName, DisplayName: "Google Special-case Crawlers", Enabled: func(s session.Session) *bool { return s.Providers.GoogleSC.Enabled }, APIKey: noKey, NewClient: googlesc.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: hetzner.ProviderName, DisplayName: "Hetzner", Enabled: func(s session.Session) *bool { return s.Providers.Hetzner.Enabled }, APIKey: noKey, NewClient: hetzner.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: ipapi.ProviderName, DisplayName: "IPAPI", Enabled: func(s session.Session) *bool { return s.Providers.IPAPI.Enabled }, APIKey: noKey, NewClient: ipapi.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: ipqs.ProviderName, DisplayName: "IPQualityScore", Enabled: func(s session.Session) *bool { return s.Providers.IPQS.Enabled }, APIKey: func(s session.Session) string { return s.Providers.IPQS.APIKey }, NewClient: ipqs.NewProviderClient, SupportsRating: true},
		{Name: iptoasn.ProviderName, DisplayName: "IPtoASN", Enabled: func(s session.Session) *bool { return s.Providers.IPToASN.Enabled }, APIKey: noKey, NewClient: iptoasn.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: ipurl.ProviderName, DisplayName: "IPURL", Enabled: func(s session.Session) *bool { return s.Providers.IPURL.Enabled }, APIKey: noKey, NewClient: ipurl.NewProviderClient, SupportsRating: true},
		{Name: icloudpr.ProviderName, DisplayName: "iCloud Private Relay", Enabled: func(s session.Session) *bool { return s.Providers.ICloudPR.Enabled }, APIKey: noKey, NewClient: icloudpr.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: linode.ProviderName, DisplayName: "Linode", Enabled: func(s session.Session) *bool { return s.Providers.Linode.Enabled }, APIKey: noKey, NewClient: linode.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: m247.ProviderName, DisplayName: "M247", Enabled: func(s session.Session) *bool { return s.Providers.M247.Enabled }, APIKey: noKey, NewClient: m247.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: openai.ProviderName, DisplayName: "OpenAI", Enabled: func(s session.Session) *bool { return s.Providers.OpenAI.Enabled }, APIKey: noKey, NewClient: openai.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: ovh.ProviderName, DisplayName: "OVH", Enabled: func(s session.Session) *bool { return s.Providers.OVH.Enabled }, APIKey: noKey, NewClient: ovh.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: scaleway.ProviderName, DisplayName: "Scaleway", Enabled: func(s session.Session) *bool { return s.Providers.Scaleway.Enabled }, APIKey: noKey, NewClient: scaleway.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: ptr.ProviderName, DisplayName: "PTR", Enabled: func(s session.Session) *bool { return s.Providers.PTR.Enabled }, APIKey: noKey, NewClient: ptr.NewProviderClient, SupportsRating: false, DefaultEnabled: true},
		{Name: shodan.ProviderName, DisplayName: "Shodan", Enabled: func(s session.Session) *bool { return s.Providers.Shodan.Enabled }, APIKey: func(s session.Session) string { return s.Providers.Shodan.APIKey }, NewClient: shodan.NewProviderClient, SupportsRating: true},
		{Name: virustotal.ProviderName, DisplayName: "VirusTotal", Enabled: func(s session.Session) *bool { return s.Providers.VirusTotal.Enabled }, APIKey: func(s session.Session) string { return s.Providers.VirusTotal.APIKey }, NewClient: virustotal.NewProviderClient, SupportsRating: true},
		{Name: vultr.ProviderName, DisplayName: "Vultr", Enabled: func(s session.Session) *bool { return s.Providers.Vultr.Enabled }, APIKey: noKey, NewClient: vultr.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: zscaler.ProviderName, DisplayName: "Zscaler", Enabled: func(s session.Session) *bool { return s.Providers.Zscaler.Enabled }, APIKey: noKey, NewClient: zscaler.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: ahrefs.ProviderName, DisplayName: "AhrefsBot", Enabled: func(s session.Session) *bool { return s.Providers.Ahrefs.Enabled }, APIKey: noKey, NewClient: ahrefs.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: akamai.ProviderName, DisplayName: "Akamai", Enabled: func(s session.Session) *bool { return s.Providers.Akamai.Enabled }, APIKey: noKey, NewClient: akamai.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: applebot.ProviderName, DisplayName: "Applebot", Enabled: func(s session.Session) *bool { return s.Providers.Applebot.Enabled }, APIKey: noKey, NewClient: applebot.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: atlassian.ProviderName, DisplayName: "Atlassian", Enabled: func(s session.Session) *bool { return s.Providers.Atlassian.Enabled }, APIKey: noKey, NewClient: atlassian.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: bunny.ProviderName, DisplayName: "Bunny CDN", Enabled: func(s session.Session) *bool { return s.Providers.Bunny.Enabled }, APIKey: noKey, NewClient: bunny.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: cdn77.ProviderName, DisplayName: "CDN77", Enabled: func(s session.Session) *bool { return s.Providers.CDN77.Enabled }, APIKey: noKey, NewClient: cdn77.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: cloudflare.ProviderName, DisplayName: "Cloudflare", Enabled: func(s session.Session) *bool { return s.Providers.Cloudflare.Enabled }, APIKey: noKey, NewClient: cloudflare.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: contabo.ProviderName, DisplayName: "Contabo", Enabled: func(s session.Session) *bool { return s.Providers.Contabo.Enabled }, APIKey: noKey, NewClient: contabo.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: datadog.ProviderName, DisplayName: "Datadog", Enabled: func(s session.Session) *bool { return s.Providers.Datadog.Enabled }, APIKey: noKey, NewClient: datadog.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: duckduckbot.ProviderName, DisplayName: "DuckDuckBot", Enabled: func(s session.Session) *bool { return s.Providers.DuckDuckBot.Enabled }, APIKey: noKey, NewClient: duckduckbot.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: fastly.ProviderName, DisplayName: "Fastly", Enabled: func(s session.Session) *bool { return s.Providers.Fastly.Enabled }, APIKey: noKey, NewClient: fastly.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: flyio.ProviderName, DisplayName: "Fly.io", Enabled: func(s session.Session) *bool { return s.Providers.Flyio.Enabled }, APIKey: noKey, NewClient: flyio.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: github.ProviderName, DisplayName: "GitHub", Enabled: func(s session.Session) *bool { return s.Providers.GitHub.Enabled }, APIKey: noKey, NewClient: github.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: googleutf.ProviderName, DisplayName: "Google User-triggered Fetchers", Enabled: func(s session.Session) *bool { return s.Providers.GoogleUTF.Enabled }, APIKey: noKey, NewClient: googleutf.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: ibmcloud.ProviderName, DisplayName: "IBM Cloud", Enabled: func(s session.Session) *bool { return s.Providers.IBMCloud.Enabled }, APIKey: noKey, NewClient: ibmcloud.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: imperva.ProviderName, DisplayName: "Imperva", Enabled: func(s session.Session) *bool { return s.Providers.Imperva.Enabled }, APIKey: noKey, NewClient: imperva.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: leaseweb.ProviderName, DisplayName: "Leaseweb", Enabled: func(s session.Session) *bool { return s.Providers.Leaseweb.Enabled }, APIKey: noKey, NewClient: leaseweb.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: oci.ProviderName, DisplayName: "Oracle Cloud (OCI)", Enabled: func(s session.Session) *bool { return s.Providers.OCI.Enabled }, APIKey: noKey, NewClient: oci.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: perplexitybot.ProviderName, DisplayName: "PerplexityBot", Enabled: func(s session.Session) *bool { return s.Providers.PerplexityBot.Enabled }, APIKey: noKey, NewClient: perplexitybot.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: render.ProviderName, DisplayName: "Render", Enabled: func(s session.Session) *bool { return s.Providers.Render.Enabled }, APIKey: noKey, NewClient: render.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: stripe.ProviderName, DisplayName: "Stripe", Enabled: func(s session.Session) *bool { return s.Providers.Stripe.Enabled }, APIKey: noKey, NewClient: stripe.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: cymru.ProviderName, DisplayName: "Team Cymru Bogons", Enabled: func(s session.Session) *bool { return s.Providers.Cymru.Enabled }, APIKey: noKey, NewClient: cymru.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: greensnow.ProviderName, DisplayName: "GreenSnow", Enabled: func(s session.Session) *bool { return s.Providers.GreenSnow.Enabled }, APIKey: noKey, NewClient: greensnow.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: tencent.ProviderName, DisplayName: "Tencent Cloud", Enabled: func(s session.Session) *bool { return s.Providers.Tencent.Enabled }, APIKey: noKey, NewClient: tencent.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: anthropic.ProviderName, DisplayName: "Anthropic", Enabled: func(s session.Session) *bool { return s.Providers.Anthropic.Enabled }, APIKey: noKey, NewClient: anthropic.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: blocklistde.ProviderName, DisplayName: "Blocklist.de", Enabled: func(s session.Session) *bool { return s.Providers.BlocklistDE.Enabled }, APIKey: noKey, NewClient: blocklistde.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: cinsscore.ProviderName, DisplayName: "CINS Army List", Enabled: func(s session.Session) *bool { return s.Providers.CINSScore.Enabled }, APIKey: noKey, NewClient: cinsscore.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: dshield.ProviderName, DisplayName: "DShield", Enabled: func(s session.Session) *bool { return s.Providers.DShield.Enabled }, APIKey: noKey, NewClient: dshield.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: emergingthreats.ProviderName, DisplayName: "Emerging Threats", Enabled: func(s session.Session) *bool { return s.Providers.EmergingThreats.Enabled }, APIKey: noKey, NewClient: emergingthreats.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: spamhaus.ProviderName, DisplayName: "Spamhaus DROP", Enabled: func(s session.Session) *bool { return s.Providers.Spamhaus.Enabled }, APIKey: noKey, NewClient: spamhaus.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
		{Name: uptimerobot.ProviderName, DisplayName: "UptimeRobot", Enabled: func(s session.Session) *bool { return s.Providers.UptimeRobot.Enabled }, APIKey: noKey, NewClient: uptimerobot.NewProviderClient, SupportsRating: true, DefaultEnabled: true},
	}
}

func noKey(_ session.Session) string { return "" }
