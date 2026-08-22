package ui

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	c "github.com/jonhadfield/ipscout/constants"
	h "github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/registry"

	"github.com/jonhadfield/ipscout/session"
	"github.com/spf13/viper"
)

var sess *session.Session

// default output priorities for providers without a constant in the
// constants package
const (
	defaultAlibabaOutputPriority  = 60
	defaultScalewayOutputPriority = 140
	defaultVultrOutputPriority    = 140
)

func ToPtr[T any](v T) *T {
	return &v
}

func addProviderConfigMessage(sess *session.Session, provider string) {
	sess.Messages.Mu.Lock()
	sess.Messages.Info = append(sess.Messages.Info, fmt.Sprintf(c.ProviderNotDefinedFmt, provider))
	sess.Messages.Mu.Unlock()
}

func initProviderConfig(sess *session.Session, v *viper.Viper) {
	// providers requiring no configuration default to enabled when absent
	// from the user's config file
	registry.SetEnabledDefaults(v)

	// IP API
	sess.Providers.IPAPI.APIKey = v.GetString("providers.ipapi.api_key")
	sess.Providers.IPAPI.ResultCacheTTL = v.GetInt64("providers.ipapi.result_cache_ttl")

	// Abuse IPDB
	if v.IsSet("providers.abuseipdb.enabled") {
		sess.Providers.AbuseIPDB.Enabled = ToPtr(v.GetBool("providers.abuseipdb.enabled"))
	} else {
		addProviderConfigMessage(sess, "AbuseIPDB")
	}

	if v.IsSet("providers.abuseipdb.output_priority") {
		sess.Providers.AbuseIPDB.OutputPriority = ToPtr(v.GetInt32("providers.abuseipdb.output_priority"))
	} else {
		sess.Providers.AbuseIPDB.OutputPriority = ToPtr(int32(c.DefaultAbuseIPDBOutputPriority))
	}

	sess.Providers.AbuseIPDB.MaxAge = v.GetInt("providers.abuseipdb.max_age")
	sess.Providers.AbuseIPDB.ResultCacheTTL = v.GetInt64("providers.abuseipdb.result_cache_ttl")

	if v.IsSet("providers.annotated.enabled") {
		sess.Providers.Annotated.Enabled = ToPtr(v.GetBool("providers.annotated.enabled"))
	} else {
		addProviderConfigMessage(sess, "Annotated")
	}

	if v.IsSet("providers.annotated.output_priority") {
		sess.Providers.Annotated.OutputPriority = ToPtr(v.GetInt32("providers.annotated.output_priority"))
	} else {
		sess.Providers.Annotated.OutputPriority = ToPtr(int32(c.DefaultAnnotatedOutputPriority))
	}

	sess.Providers.Annotated.Paths = v.GetStringSlice("providers.annotated.paths")
	sess.Providers.Annotated.DocumentCacheTTL = v.GetInt64("providers.annotated.document_cache_ttl")

	if v.IsSet("providers.aws.enabled") {
		sess.Providers.AWS.Enabled = ToPtr(v.GetBool("providers.aws.enabled"))
	} else {
		addProviderConfigMessage(sess, "AWS")
	}

	if v.IsSet("providers.aws.output_priority") {
		sess.Providers.AWS.OutputPriority = ToPtr(v.GetInt32("providers.aws.output_priority"))
	} else {
		sess.Providers.AWS.OutputPriority = ToPtr(int32(c.DefaultAWSOutputPriority))
	}

	sess.Providers.AWS.URL = v.GetString("providers.aws.url")
	sess.Providers.AWS.DocumentCacheTTL = v.GetInt64("providers.aws.document_cache_ttl")

	// Azure
	if v.IsSet("providers.azure.enabled") {
		sess.Providers.Azure.Enabled = ToPtr(v.GetBool("providers.azure.enabled"))
	} else {
		addProviderConfigMessage(sess, "Azure")
	}

	if v.IsSet("providers.azure.output_priority") {
		sess.Providers.Azure.OutputPriority = ToPtr(v.GetInt32("providers.azure.output_priority"))
	} else {
		sess.Providers.Azure.OutputPriority = ToPtr(int32(c.DefaultAzureOutputPriority))
	}

	sess.Providers.Azure.URL = v.GetString("providers.azure.url")

	sess.Providers.Azure.DocumentCacheTTL = v.GetInt64("providers.azure.document_cache_ttl")

	// AzureWAF
	if v.IsSet("providers.azurewaf.enabled") {
		sess.Providers.AzureWAF.Enabled = ToPtr(v.GetBool("providers.azurewaf.enabled"))
	} else {
		addProviderConfigMessage(sess, "Azure WAF")
	}

	if v.IsSet("providers.azurewaf.output_priority") {
		sess.Providers.AzureWAF.OutputPriority = ToPtr(v.GetInt32("providers.azurewaf.output_priority"))
	} else {
		sess.Providers.AzureWAF.OutputPriority = ToPtr(int32(c.DefaultAzureWAFOutputPriority))
	}

	sess.Providers.AzureWAF.ResourceIDs = v.GetStringSlice("providers.azurewaf.resource_ids")

	sess.Providers.AzureWAF.DocumentCacheTTL = v.GetInt64("providers.azurewaf.document_cache_ttl")

	// CriminalIP
	if v.IsSet("providers.criminalip.enabled") {
		sess.Providers.CriminalIP.Enabled = ToPtr(v.GetBool("providers.criminalip.enabled"))
	} else {
		addProviderConfigMessage(sess, "Criminal IP")
	}

	if v.IsSet("providers.criminalip.output_priority") {
		sess.Providers.CriminalIP.OutputPriority = ToPtr(v.GetInt32("providers.criminalip.output_priority"))
	} else {
		sess.Providers.CriminalIP.OutputPriority = ToPtr(int32(c.DefaultCriminalIPOutputPriority))
	}

	sess.Providers.CriminalIP.ResultCacheTTL = v.GetInt64("providers.criminalip.result_cache_ttl")

	// BingBot
	if v.IsSet("providers.bingbot.enabled") {
		sess.Providers.Bingbot.Enabled = ToPtr(v.GetBool("providers.bingbot.enabled"))
	} else {
		addProviderConfigMessage(sess, "Bingbot")
	}

	if v.IsSet("providers.bingbot.output_priority") {
		sess.Providers.Bingbot.OutputPriority = ToPtr(v.GetInt32("providers.bingbot.output_priority"))
	} else {
		sess.Providers.Bingbot.OutputPriority = ToPtr(int32(c.DefaultBingbotOutputPriority))
	}

	sess.Providers.Bingbot.URL = v.GetString("providers.bingbot.url")

	sess.Providers.Bingbot.DocumentCacheTTL = v.GetInt64("providers.bingbot.document_cache_ttl")

	// DigitalOcean
	if v.IsSet("providers.digitalocean.enabled") {
		sess.Providers.DigitalOcean.Enabled = ToPtr(v.GetBool("providers.digitalocean.enabled"))
	} else {
		addProviderConfigMessage(sess, "DigitalOcean")
	}

	if v.IsSet("providers.digitalocean.output_priority") {
		sess.Providers.DigitalOcean.OutputPriority = ToPtr(v.GetInt32("providers.digitalocean.output_priority"))
	} else {
		sess.Providers.DigitalOcean.OutputPriority = ToPtr(int32(c.DefaultDigitalOceanOutputPriority))
	}

	sess.Providers.DigitalOcean.URL = v.GetString("providers.digitalocean.url")
	sess.Providers.DigitalOcean.DocumentCacheTTL = v.GetInt64("providers.digitalocean.document_cache_ttl")

	// GCP
	if v.IsSet("providers.gcp.enabled") {
		sess.Providers.GCP.Enabled = ToPtr(v.GetBool("providers.gcp.enabled"))
	} else {
		addProviderConfigMessage(sess, "GCP")
	}

	if v.IsSet("providers.gcp.output_priority") {
		sess.Providers.GCP.OutputPriority = ToPtr(v.GetInt32("providers.gcp.output_priority"))
	} else {
		sess.Providers.GCP.OutputPriority = ToPtr(int32(c.DefaultGCPOutputPriority))
	}

	sess.Providers.GCP.URL = v.GetString("providers.gcp.url")
	sess.Providers.GCP.DocumentCacheTTL = v.GetInt64("providers.gcp.document_cache_ttl")

	// Google
	if v.IsSet("providers.google.enabled") {
		sess.Providers.Google.Enabled = ToPtr(v.GetBool("providers.google.enabled"))
	} else {
		addProviderConfigMessage(sess, "Google")
	}

	if v.IsSet("providers.google.output_priority") {
		sess.Providers.Google.OutputPriority = ToPtr(v.GetInt32("providers.google.output_priority"))
	} else {
		sess.Providers.Google.OutputPriority = ToPtr(int32(c.DefaultGoogleOutputPriority))
	}

	// Googlebot
	if v.IsSet("providers.googlebot.enabled") {
		sess.Providers.Googlebot.Enabled = ToPtr(v.GetBool("providers.googlebot.enabled"))
	} else {
		addProviderConfigMessage(sess, "Googlebot")
	}

	if v.IsSet("providers.googlebot.output_priority") {
		sess.Providers.Googlebot.OutputPriority = ToPtr(v.GetInt32("providers.Googlebot.output_priority"))
	} else {
		sess.Providers.Googlebot.OutputPriority = ToPtr(int32(c.DefaultGooglebotOutputPriority))
	}

	sess.Providers.Googlebot.URL = v.GetString("providers.googlebot.url")

	// GoogleSC
	if v.IsSet("providers.googlesc.enabled") {
		sess.Providers.GoogleSC.Enabled = ToPtr(v.GetBool("providers.googlesc.enabled"))
	} else {
		addProviderConfigMessage(sess, "GoogleSC")
	}

	if v.IsSet("providers.googlesc.output_priority") {
		sess.Providers.GoogleSC.OutputPriority = ToPtr(v.GetInt32("providers.GoogleSC.output_priority"))
	} else {
		sess.Providers.GoogleSC.OutputPriority = ToPtr(int32(c.DefaultGoogleSCOutputPriority))
	}

	sess.Providers.GoogleSC.URL = v.GetString("providers.googlesc.url")

	// Hetzner
	if v.IsSet("providers.hetzner.enabled") {
		sess.Providers.Hetzner.Enabled = ToPtr(v.GetBool("providers.hetzner.enabled"))
	} else {
		addProviderConfigMessage(sess, "Hetzner")
	}

	if v.IsSet("providers.hetzner.output_priority") {
		sess.Providers.Hetzner.OutputPriority = ToPtr(v.GetInt32("providers.hetzner.output_priority"))
	} else {
		sess.Providers.Hetzner.OutputPriority = ToPtr(int32(c.DefaultHetznerOutputPriority))
	}

	// iCloud Private Relay
	if v.IsSet("providers.icloudpr.enabled") {
		sess.Providers.ICloudPR.Enabled = ToPtr(v.GetBool("providers.icloudpr.enabled"))
	} else {
		addProviderConfigMessage(sess, "iCloud Private Relay")
	}

	if v.IsSet("providers.icloudpr.output_priority") {
		sess.Providers.ICloudPR.OutputPriority = ToPtr(v.GetInt32("providers.icloudpr.output_priority"))
	} else {
		sess.Providers.ICloudPR.OutputPriority = ToPtr(int32(c.DefaultiCloudPROutputPriority))
	}

	sess.Providers.ICloudPR.URL = v.GetString("providers.icloudpr.url")
	sess.Providers.ICloudPR.DocumentCacheTTL = v.GetInt64("providers.icloudpr.document_cache_ttl")

	// IPQS
	if v.IsSet("providers.ipqs.enabled") {
		sess.Providers.IPQS.Enabled = ToPtr(v.GetBool("providers.ipqs.enabled"))
	} else {
		addProviderConfigMessage(sess, "IPQS")
	}

	if v.IsSet("providers.ipqs.output_priority") {
		sess.Providers.IPQS.OutputPriority = ToPtr(v.GetInt32("providers.ipqs.output_priority"))
	} else {
		sess.Providers.IPQS.OutputPriority = ToPtr(int32(c.DefaultIPQSOutputPriority))
	}

	if v.IsSet("providers.ipqs.api_key") {
		sess.Providers.IPQS.APIKey = v.GetString("providers.ipqs.api_key")
	}

	sess.Providers.IPQS.ResultCacheTTL = v.GetInt64("providers.ipqs.result_cache_ttl")

	// IP URL
	if v.IsSet("providers.ipurl.enabled") {
		sess.Providers.IPURL.Enabled = ToPtr(v.GetBool("providers.ipurl.enabled"))
	} else {
		addProviderConfigMessage(sess, "IP URL")
	}

	if v.IsSet("providers.ipurl.output_priority") {
		sess.Providers.IPURL.OutputPriority = ToPtr(v.GetInt32("providers.ipurl.output_priority"))
	} else {
		sess.Providers.IPURL.OutputPriority = ToPtr(int32(c.DefaultIPURLOutputPriority))
	}

	sess.Providers.IPURL.URLs = v.GetStringSlice("providers.ipurl.urls")
	sess.Providers.IPURL.DocumentCacheTTL = v.GetInt64("providers.ipurl.document_cache_ttl")

	// Linode
	if v.IsSet("providers.linode.enabled") {
		sess.Providers.Linode.Enabled = ToPtr(v.GetBool("providers.linode.enabled"))
	} else {
		addProviderConfigMessage(sess, "Linode")
	}

	if v.IsSet("providers.linode.output_priority") {
		sess.Providers.Linode.OutputPriority = ToPtr(v.GetInt32("providers.linode.output_priority"))
	} else {
		sess.Providers.Linode.OutputPriority = ToPtr(int32(c.DefaultLinodeOutputPriority))
	}

	sess.Providers.Linode.DocumentCacheTTL = v.GetInt64("providers.linode.document_cache_ttl")
	sess.Providers.Linode.URL = v.GetString("providers.linode.url")

	// M247
	if v.IsSet("providers.m247.enabled") {
		sess.Providers.M247.Enabled = ToPtr(v.GetBool("providers.m247.enabled"))
	} else {
		addProviderConfigMessage(sess, "M247")
	}

	if v.IsSet("providers.m247.output_priority") {
		sess.Providers.M247.OutputPriority = ToPtr(v.GetInt32("providers.m247.output_priority"))
	} else {
		sess.Providers.M247.OutputPriority = ToPtr(int32(c.DefaultM247OutputPriority))
	}

	sess.Providers.M247.DocumentCacheTTL = v.GetInt64("providers.m247.document_cache_ttl")
	sess.Providers.M247.URL = v.GetString("providers.m247.url")

	// OpenAI
	if v.IsSet("providers.openai.enabled") {
		sess.Providers.OpenAI.Enabled = ToPtr(v.GetBool("providers.openai.enabled"))
	} else {
		addProviderConfigMessage(sess, "OpenAI")
	}

	if v.IsSet("providers.openai.output_priority") {
		sess.Providers.OpenAI.OutputPriority = ToPtr(v.GetInt32("providers.openai.output_priority"))
	} else {
		sess.Providers.OpenAI.OutputPriority = ToPtr(int32(c.DefaultOpenAIOutputPriority))
	}

	sess.Providers.OpenAI.DocumentCacheTTL = v.GetInt64("providers.openai.document_cache_ttl")
	sess.Providers.OpenAI.GPTBotURL = v.GetString("providers.openai.gptbot_url")
	sess.Providers.OpenAI.SearchBotURL = v.GetString("providers.openai.searchbot_url")
	sess.Providers.OpenAI.ChatGPTUserURL = v.GetString("providers.openai.chatgpt_user_url")

	// OVH
	if v.IsSet("providers.ovh.enabled") {
		sess.Providers.OVH.Enabled = ToPtr(v.GetBool("providers.ovh.enabled"))
	} else {
		addProviderConfigMessage(sess, "OVH")
	}

	if v.IsSet("providers.ovh.output_priority") {
		sess.Providers.OVH.OutputPriority = ToPtr(v.GetInt32("providers.ovh.output_priority"))
	} else {
		sess.Providers.OVH.OutputPriority = ToPtr(int32(c.DefaultOVHOutputPriority))
	}

	sess.Providers.OVH.DocumentCacheTTL = v.GetInt64("providers.ovh.document_cache_ttl")
	sess.Providers.OVH.URL = v.GetString("providers.ovh.url")

	// Shodan
	if v.IsSet("providers.shodan.enabled") {
		sess.Providers.Shodan.Enabled = ToPtr(v.GetBool("providers.shodan.enabled"))
	} else {
		addProviderConfigMessage(sess, "Shodan")
	}

	if v.IsSet("providers.shodan.output_priority") {
		sess.Providers.Shodan.OutputPriority = ToPtr(v.GetInt32("providers.shodan.output_priority"))
	} else {
		sess.Providers.Shodan.OutputPriority = ToPtr(int32(c.DefaultShodanOutputPriority))
	}

	if v.IsSet("providers.shodan.api_key") {
		sess.Providers.Shodan.APIKey = v.GetString("providers.shodan.api_key")
	}

	sess.Providers.Shodan.ResultCacheTTL = v.GetInt64("providers.shodan.result_cache_ttl")

	// PTR
	if v.IsSet("providers.ptr.enabled") {
		sess.Providers.PTR.Enabled = ToPtr(v.GetBool("providers.ptr.enabled"))
	} else {
		addProviderConfigMessage(sess, "PTR")
	}

	if v.IsSet("providers.ptr.output_priority") {
		sess.Providers.PTR.OutputPriority = ToPtr(v.GetInt32("providers.ptr.output_priority"))
	} else {
		sess.Providers.PTR.OutputPriority = ToPtr(int32(c.DefaultPtrOutputPriority))
	}

	sess.Providers.PTR.ResultCacheTTL = v.GetInt64("providers.ptr.result_cache_ttl")
	sess.Providers.PTR.Nameservers = v.GetStringSlice("providers.ptr.nameservers")

	// IPAPI
	if v.IsSet("providers.ipapi.enabled") {
		sess.Providers.IPAPI.Enabled = ToPtr(v.GetBool("providers.ipapi.enabled"))
	} else {
		addProviderConfigMessage(sess, "IPAPI")
	}

	if v.IsSet("providers.ipapi.output_priority") {
		sess.Providers.IPAPI.OutputPriority = ToPtr(v.GetInt32("providers.ipapi.output_priority"))
	} else {
		sess.Providers.IPAPI.OutputPriority = ToPtr(int32(c.DefaultIPAPIOutputPriority))
	}

	// IPtoASN
	if v.IsSet("providers.iptoasn.enabled") {
		sess.Providers.IPToASN.Enabled = ToPtr(v.GetBool("providers.iptoasn.enabled"))
	} else {
		addProviderConfigMessage(sess, "IPtoASN")
	}

	if v.IsSet("providers.iptoasn.output_priority") {
		sess.Providers.IPToASN.OutputPriority = ToPtr(v.GetInt32("providers.iptoasn.output_priority"))
	} else {
		sess.Providers.IPToASN.OutputPriority = ToPtr(int32(c.DefaultIPToASNOutputPriority))
	}

	sess.Providers.IPToASN.URL = v.GetString("providers.iptoasn.url")
	sess.Providers.IPToASN.DocumentCacheTTL = v.GetInt64("providers.iptoasn.document_cache_ttl")

	// VirusTotal
	if v.IsSet("providers.virustotal.enabled") {
		sess.Providers.VirusTotal.Enabled = ToPtr(v.GetBool("providers.virustotal.enabled"))
		sess.Providers.VirusTotal.ResultCacheTTL = v.GetInt64("providers.virustotal.result_cache_ttl")
		sess.Providers.VirusTotal.ShowProviders = ToPtr(v.GetBool("providers.virustotal.show_providers"))
		sess.Providers.VirusTotal.ShowUnrated = ToPtr(v.GetBool("providers.virustotal.show_unrated"))
		sess.Providers.VirusTotal.ShowHarmless = ToPtr(v.GetBool("providers.virustotal.show_harmless"))
		sess.Providers.VirusTotal.ShowClean = ToPtr(v.GetBool("providers.virustotal.show_clean"))
	} else {
		addProviderConfigMessage(sess, "VirusTotal")
	}

	if v.IsSet("providers.virustotal.output_priority") {
		sess.Providers.VirusTotal.OutputPriority = ToPtr(v.GetInt32("providers.virustotal.output_priority"))
	} else {
		sess.Providers.VirusTotal.OutputPriority = ToPtr(int32(c.DefaultVirusTotalOutputPriority))
	}

	// Zscaler
	if v.IsSet("providers.zscaler.enabled") {
		sess.Providers.Zscaler.Enabled = ToPtr(v.GetBool("providers.zscaler.enabled"))
	} else {
		addProviderConfigMessage(sess, "Zscaler")
	}

	if v.IsSet("providers.zscaler.output_priority") {
		sess.Providers.Zscaler.OutputPriority = ToPtr(v.GetInt32("providers.zscaler.output_priority"))
	} else {
		sess.Providers.Zscaler.OutputPriority = ToPtr(int32(c.DefaultZscalerOutputPriority))
	}

	sess.Providers.Zscaler.DocumentCacheTTL = v.GetInt64("providers.zscaler.document_cache_ttl")
	sess.Providers.Zscaler.URL = v.GetString("providers.zscaler.url")

	// AhrefsBot
	if v.IsSet("providers.ahrefs.enabled") {
		sess.Providers.Ahrefs.Enabled = ToPtr(v.GetBool("providers.ahrefs.enabled"))
	} else {
		addProviderConfigMessage(sess, "AhrefsBot")
	}

	if v.IsSet("providers.ahrefs.output_priority") {
		sess.Providers.Ahrefs.OutputPriority = ToPtr(v.GetInt32("providers.ahrefs.output_priority"))
	} else {
		sess.Providers.Ahrefs.OutputPriority = ToPtr(int32(c.DefaultAhrefsOutputPriority))
	}

	sess.Providers.Ahrefs.DocumentCacheTTL = v.GetInt64("providers.ahrefs.document_cache_ttl")

	// Akamai
	if v.IsSet("providers.akamai.enabled") {
		sess.Providers.Akamai.Enabled = ToPtr(v.GetBool("providers.akamai.enabled"))
	} else {
		addProviderConfigMessage(sess, "Akamai")
	}

	if v.IsSet("providers.akamai.output_priority") {
		sess.Providers.Akamai.OutputPriority = ToPtr(v.GetInt32("providers.akamai.output_priority"))
	} else {
		sess.Providers.Akamai.OutputPriority = ToPtr(int32(c.DefaultAkamaiOutputPriority))
	}

	sess.Providers.Akamai.DocumentCacheTTL = v.GetInt64("providers.akamai.document_cache_ttl")

	// Applebot
	if v.IsSet("providers.applebot.enabled") {
		sess.Providers.Applebot.Enabled = ToPtr(v.GetBool("providers.applebot.enabled"))
	} else {
		addProviderConfigMessage(sess, "Applebot")
	}

	if v.IsSet("providers.applebot.output_priority") {
		sess.Providers.Applebot.OutputPriority = ToPtr(v.GetInt32("providers.applebot.output_priority"))
	} else {
		sess.Providers.Applebot.OutputPriority = ToPtr(int32(c.DefaultApplebotOutputPriority))
	}

	sess.Providers.Applebot.DocumentCacheTTL = v.GetInt64("providers.applebot.document_cache_ttl")

	// Cloudflare
	if v.IsSet("providers.cloudflare.enabled") {
		sess.Providers.Cloudflare.Enabled = ToPtr(v.GetBool("providers.cloudflare.enabled"))
	} else {
		addProviderConfigMessage(sess, "Cloudflare")
	}

	if v.IsSet("providers.cloudflare.output_priority") {
		sess.Providers.Cloudflare.OutputPriority = ToPtr(v.GetInt32("providers.cloudflare.output_priority"))
	} else {
		sess.Providers.Cloudflare.OutputPriority = ToPtr(int32(c.DefaultCloudflareOutputPriority))
	}

	sess.Providers.Cloudflare.DocumentCacheTTL = v.GetInt64("providers.cloudflare.document_cache_ttl")

	// DuckDuckBot
	if v.IsSet("providers.duckduckbot.enabled") {
		sess.Providers.DuckDuckBot.Enabled = ToPtr(v.GetBool("providers.duckduckbot.enabled"))
	} else {
		addProviderConfigMessage(sess, "DuckDuckBot")
	}

	if v.IsSet("providers.duckduckbot.output_priority") {
		sess.Providers.DuckDuckBot.OutputPriority = ToPtr(v.GetInt32("providers.duckduckbot.output_priority"))
	} else {
		sess.Providers.DuckDuckBot.OutputPriority = ToPtr(int32(c.DefaultDuckDuckBotOutputPriority))
	}

	sess.Providers.DuckDuckBot.DocumentCacheTTL = v.GetInt64("providers.duckduckbot.document_cache_ttl")

	// Fastly
	if v.IsSet("providers.fastly.enabled") {
		sess.Providers.Fastly.Enabled = ToPtr(v.GetBool("providers.fastly.enabled"))
	} else {
		addProviderConfigMessage(sess, "Fastly")
	}

	if v.IsSet("providers.fastly.output_priority") {
		sess.Providers.Fastly.OutputPriority = ToPtr(v.GetInt32("providers.fastly.output_priority"))
	} else {
		sess.Providers.Fastly.OutputPriority = ToPtr(int32(c.DefaultFastlyOutputPriority))
	}

	sess.Providers.Fastly.DocumentCacheTTL = v.GetInt64("providers.fastly.document_cache_ttl")

	// GitHub
	if v.IsSet("providers.github.enabled") {
		sess.Providers.GitHub.Enabled = ToPtr(v.GetBool("providers.github.enabled"))
	} else {
		addProviderConfigMessage(sess, "GitHub")
	}

	if v.IsSet("providers.github.output_priority") {
		sess.Providers.GitHub.OutputPriority = ToPtr(v.GetInt32("providers.github.output_priority"))
	} else {
		sess.Providers.GitHub.OutputPriority = ToPtr(int32(c.DefaultGitHubOutputPriority))
	}

	sess.Providers.GitHub.DocumentCacheTTL = v.GetInt64("providers.github.document_cache_ttl")

	// Google User-triggered Fetchers
	if v.IsSet("providers.googleutf.enabled") {
		sess.Providers.GoogleUTF.Enabled = ToPtr(v.GetBool("providers.googleutf.enabled"))
	} else {
		addProviderConfigMessage(sess, "Google User-triggered Fetchers")
	}

	if v.IsSet("providers.googleutf.output_priority") {
		sess.Providers.GoogleUTF.OutputPriority = ToPtr(v.GetInt32("providers.googleutf.output_priority"))
	} else {
		sess.Providers.GoogleUTF.OutputPriority = ToPtr(int32(c.DefaultGoogleUTFOutputPriority))
	}

	sess.Providers.GoogleUTF.DocumentCacheTTL = v.GetInt64("providers.googleutf.document_cache_ttl")

	// Oracle Cloud (OCI)
	if v.IsSet("providers.oci.enabled") {
		sess.Providers.OCI.Enabled = ToPtr(v.GetBool("providers.oci.enabled"))
	} else {
		addProviderConfigMessage(sess, "Oracle Cloud (OCI)")
	}

	if v.IsSet("providers.oci.output_priority") {
		sess.Providers.OCI.OutputPriority = ToPtr(v.GetInt32("providers.oci.output_priority"))
	} else {
		sess.Providers.OCI.OutputPriority = ToPtr(int32(c.DefaultOCIOutputPriority))
	}

	sess.Providers.OCI.DocumentCacheTTL = v.GetInt64("providers.oci.document_cache_ttl")

	// PerplexityBot
	if v.IsSet("providers.perplexitybot.enabled") {
		sess.Providers.PerplexityBot.Enabled = ToPtr(v.GetBool("providers.perplexitybot.enabled"))
	} else {
		addProviderConfigMessage(sess, "PerplexityBot")
	}

	if v.IsSet("providers.perplexitybot.output_priority") {
		sess.Providers.PerplexityBot.OutputPriority = ToPtr(v.GetInt32("providers.perplexitybot.output_priority"))
	} else {
		sess.Providers.PerplexityBot.OutputPriority = ToPtr(int32(c.DefaultPerplexityBotOutputPriority))
	}

	sess.Providers.PerplexityBot.DocumentCacheTTL = v.GetInt64("providers.perplexitybot.document_cache_ttl")

	// Anthropic
	if v.IsSet("providers.anthropic.enabled") {
		sess.Providers.Anthropic.Enabled = ToPtr(v.GetBool("providers.anthropic.enabled"))
	} else {
		addProviderConfigMessage(sess, "Anthropic")
	}

	if v.IsSet("providers.anthropic.output_priority") {
		sess.Providers.Anthropic.OutputPriority = ToPtr(v.GetInt32("providers.anthropic.output_priority"))
	} else {
		sess.Providers.Anthropic.OutputPriority = ToPtr(int32(c.DefaultAnthropicOutputPriority))
	}

	sess.Providers.Anthropic.DocumentCacheTTL = v.GetInt64("providers.anthropic.document_cache_ttl")

	// Blocklist.de
	if v.IsSet("providers.blocklistde.enabled") {
		sess.Providers.BlocklistDE.Enabled = ToPtr(v.GetBool("providers.blocklistde.enabled"))
	} else {
		addProviderConfigMessage(sess, "Blocklist.de")
	}

	if v.IsSet("providers.blocklistde.output_priority") {
		sess.Providers.BlocklistDE.OutputPriority = ToPtr(v.GetInt32("providers.blocklistde.output_priority"))
	} else {
		sess.Providers.BlocklistDE.OutputPriority = ToPtr(int32(c.DefaultBlocklistDEOutputPriority))
	}

	sess.Providers.BlocklistDE.DocumentCacheTTL = v.GetInt64("providers.blocklistde.document_cache_ttl")

	// CINS Army List
	if v.IsSet("providers.cinsscore.enabled") {
		sess.Providers.CINSScore.Enabled = ToPtr(v.GetBool("providers.cinsscore.enabled"))
	} else {
		addProviderConfigMessage(sess, "CINS Army List")
	}

	if v.IsSet("providers.cinsscore.output_priority") {
		sess.Providers.CINSScore.OutputPriority = ToPtr(v.GetInt32("providers.cinsscore.output_priority"))
	} else {
		sess.Providers.CINSScore.OutputPriority = ToPtr(int32(c.DefaultCINSScoreOutputPriority))
	}

	sess.Providers.CINSScore.DocumentCacheTTL = v.GetInt64("providers.cinsscore.document_cache_ttl")

	// DShield
	if v.IsSet("providers.dshield.enabled") {
		sess.Providers.DShield.Enabled = ToPtr(v.GetBool("providers.dshield.enabled"))
	} else {
		addProviderConfigMessage(sess, "DShield")
	}

	if v.IsSet("providers.dshield.output_priority") {
		sess.Providers.DShield.OutputPriority = ToPtr(v.GetInt32("providers.dshield.output_priority"))
	} else {
		sess.Providers.DShield.OutputPriority = ToPtr(int32(c.DefaultDShieldOutputPriority))
	}

	sess.Providers.DShield.DocumentCacheTTL = v.GetInt64("providers.dshield.document_cache_ttl")

	// Emerging Threats
	if v.IsSet("providers.emergingthreats.enabled") {
		sess.Providers.EmergingThreats.Enabled = ToPtr(v.GetBool("providers.emergingthreats.enabled"))
	} else {
		addProviderConfigMessage(sess, "Emerging Threats")
	}

	if v.IsSet("providers.emergingthreats.output_priority") {
		sess.Providers.EmergingThreats.OutputPriority = ToPtr(v.GetInt32("providers.emergingthreats.output_priority"))
	} else {
		sess.Providers.EmergingThreats.OutputPriority = ToPtr(int32(c.DefaultEmergingThreatsOutputPriority))
	}

	sess.Providers.EmergingThreats.DocumentCacheTTL = v.GetInt64("providers.emergingthreats.document_cache_ttl")

	// Spamhaus DROP
	if v.IsSet("providers.spamhaus.enabled") {
		sess.Providers.Spamhaus.Enabled = ToPtr(v.GetBool("providers.spamhaus.enabled"))
	} else {
		addProviderConfigMessage(sess, "Spamhaus DROP")
	}

	if v.IsSet("providers.spamhaus.output_priority") {
		sess.Providers.Spamhaus.OutputPriority = ToPtr(v.GetInt32("providers.spamhaus.output_priority"))
	} else {
		sess.Providers.Spamhaus.OutputPriority = ToPtr(int32(c.DefaultSpamhausOutputPriority))
	}

	sess.Providers.Spamhaus.DocumentCacheTTL = v.GetInt64("providers.spamhaus.document_cache_ttl")

	// UptimeRobot
	if v.IsSet("providers.uptimerobot.enabled") {
		sess.Providers.UptimeRobot.Enabled = ToPtr(v.GetBool("providers.uptimerobot.enabled"))
	} else {
		addProviderConfigMessage(sess, "UptimeRobot")
	}

	if v.IsSet("providers.uptimerobot.output_priority") {
		sess.Providers.UptimeRobot.OutputPriority = ToPtr(v.GetInt32("providers.uptimerobot.output_priority"))
	} else {
		sess.Providers.UptimeRobot.OutputPriority = ToPtr(int32(c.DefaultUptimeRobotOutputPriority))
	}

	sess.Providers.UptimeRobot.DocumentCacheTTL = v.GetInt64("providers.uptimerobot.document_cache_ttl")

	initSimpleProviderConfig(sess, v, "alibaba", "Alibaba", defaultAlibabaOutputPriority,
		&sess.Providers.Alibaba.Enabled, &sess.Providers.Alibaba.OutputPriority, &sess.Providers.Alibaba.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "atlassian", "Atlassian", c.DefaultAtlassianOutputPriority,
		&sess.Providers.Atlassian.Enabled, &sess.Providers.Atlassian.OutputPriority, &sess.Providers.Atlassian.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "bunny", "Bunny CDN", c.DefaultBunnyOutputPriority,
		&sess.Providers.Bunny.Enabled, &sess.Providers.Bunny.OutputPriority, &sess.Providers.Bunny.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "cdn77", "CDN77", c.DefaultCDN77OutputPriority,
		&sess.Providers.CDN77.Enabled, &sess.Providers.CDN77.OutputPriority, &sess.Providers.CDN77.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "contabo", "Contabo", c.DefaultContaboOutputPriority,
		&sess.Providers.Contabo.Enabled, &sess.Providers.Contabo.OutputPriority, &sess.Providers.Contabo.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "datadog", "Datadog", c.DefaultDatadogOutputPriority,
		&sess.Providers.Datadog.Enabled, &sess.Providers.Datadog.OutputPriority, &sess.Providers.Datadog.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "flyio", "Fly.io", c.DefaultFlyioOutputPriority,
		&sess.Providers.Flyio.Enabled, &sess.Providers.Flyio.OutputPriority, &sess.Providers.Flyio.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "ibmcloud", "IBM Cloud", c.DefaultIBMCloudOutputPriority,
		&sess.Providers.IBMCloud.Enabled, &sess.Providers.IBMCloud.OutputPriority, &sess.Providers.IBMCloud.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "imperva", "Imperva", c.DefaultImpervaOutputPriority,
		&sess.Providers.Imperva.Enabled, &sess.Providers.Imperva.OutputPriority, &sess.Providers.Imperva.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "leaseweb", "Leaseweb", c.DefaultLeasewebOutputPriority,
		&sess.Providers.Leaseweb.Enabled, &sess.Providers.Leaseweb.OutputPriority, &sess.Providers.Leaseweb.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "render", "Render", c.DefaultRenderOutputPriority,
		&sess.Providers.Render.Enabled, &sess.Providers.Render.OutputPriority, &sess.Providers.Render.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "scaleway", "Scaleway", defaultScalewayOutputPriority,
		&sess.Providers.Scaleway.Enabled, &sess.Providers.Scaleway.OutputPriority, &sess.Providers.Scaleway.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "stripe", "Stripe", c.DefaultStripeOutputPriority,
		&sess.Providers.Stripe.Enabled, &sess.Providers.Stripe.OutputPriority, &sess.Providers.Stripe.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "tencent", "Tencent Cloud", c.DefaultTencentOutputPriority,
		&sess.Providers.Tencent.Enabled, &sess.Providers.Tencent.OutputPriority, &sess.Providers.Tencent.DocumentCacheTTL)
	initSimpleProviderConfig(sess, v, "vultr", "Vultr", defaultVultrOutputPriority,
		&sess.Providers.Vultr.Enabled, &sess.Providers.Vultr.OutputPriority, &sess.Providers.Vultr.DocumentCacheTTL)

	// alibaba, scaleway and vultr allow the source URL to be overridden
	sess.Providers.Alibaba.URL = v.GetString("providers.alibaba.url")
	sess.Providers.Scaleway.URL = v.GetString("providers.scaleway.url")
	sess.Providers.Vultr.URL = v.GetString("providers.vultr.url")
}

// initSimpleProviderConfig wires a provider with the common enabled /
// output_priority / document_cache_ttl config shape into the session, so that
// providers registered in the registry are actually read from config.
func initSimpleProviderConfig(sess *session.Session, v *viper.Viper, key, displayName string, defaultPriority int32, enabled **bool, priority **int32, docCacheTTL *int64) {
	if v.IsSet("providers." + key + ".enabled") {
		*enabled = ToPtr(v.GetBool("providers." + key + ".enabled"))
	} else {
		addProviderConfigMessage(sess, displayName)
	}

	if v.IsSet("providers." + key + ".output_priority") {
		*priority = ToPtr(v.GetInt32("providers." + key + ".output_priority"))
	} else {
		*priority = ToPtr(defaultPriority)
	}

	*docCacheTTL = v.GetInt64("providers." + key + ".document_cache_ttl")
}

func initSessionConfig(sess *session.Session, v *viper.Viper) {
	initProviderConfig(sess, v)

	sess.Config.Global.Ports = v.GetStringSlice("global.ports")
	sess.Config.Global.MaxValueChars = v.GetInt32("global.max_value_chars")

	sess.Config.Global.MaxAge = v.GetString("global.max_age")
	sess.Config.Global.MaxReports = v.GetInt("global.max_reports")

	if len(sess.Config.Global.Ports) == 1 && sess.Config.Global.Ports[0] == "[]" {
		sess.Config.Global.Ports = nil
	}

	sess.Config.Global.MaxAge = v.GetString("global.max_age")

	sess.Config.Rating.ConfigPath = v.GetString("rating.config_path")
	sess.Config.Rating.UseAI = v.GetBool("rating.use_ai")
	sess.Config.Rating.OpenAIAPIKey = v.GetString("rating.openai_api_key")
}

func initConfig(logLevel string) (*session.Session, error) {
	v := viper.New()

	// create session
	sess = session.New()

	// get home dir to be used for config and cache
	if err := h.InitHomeDirConfig(sess, v); err != nil {
		return sess, fmt.Errorf("home dir initialization error: %w", err)
	}

	configRoot := session.GetConfigRoot("", sess.Config.Global.HomeDir, c.AppName)
	sess.App.Version = h.Version
	sess.App.SemVer = h.SemVer

	if _, err := session.CreateDefaultConfigIfMissing(configRoot); err != nil {
		return sess, fmt.Errorf("cannot create default session: %w", err)
	}

	// add any providers introduced since the user's config was written, so
	// their config shows all no-config providers as enabled
	if _, err := registry.EnsureDefaultProvidersInConfig(filepath.Join(configRoot, session.DefaultConfigFileName)); err != nil {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, fmt.Sprintf("unable to add new providers to config: %s", err))
		sess.Messages.Mu.Unlock()
	}

	v.AddConfigPath(configRoot)
	v.SetConfigName("config")

	if err := v.ReadInConfig(); err != nil {
		return sess, fmt.Errorf("cannot read session: %w", err)
	}

	v.AutomaticEnv()

	if err := session.CreateConfigPathStructure(configRoot); err != nil {
		return sess, fmt.Errorf("can't create cache directory: %w", err)
	}

	readProviderAuthKeys(v)

	sess.Target = os.Stderr

	initSessionConfig(sess, v)

	// initialise logging
	if err := initLogging(logLevel); err != nil {
		return sess, err
	}

	sess.HTTPClient = h.GetHTTPClient()

	// utd, err := cmd.Flags().GetBool("use-test-data")
	// if err != nil {
	// 	return sess, fmt.Errorf("error getting use-test-data: %w", err)
	// }
	//
	// sess.UseTestData = utd

	// ports, _ := cmd.Flags().GetStringSlice("ports")
	// if len(ports) == 1 && ports[0] == "[]" {
	// 	ports = nil
	// }
	// // if no ports specified on cli then default to global ports
	// if len(ports) > 0 {
	// 	sess.Config.Global.Ports = ports
	// }
	//
	// maxAge, _ := cmd.Flags().GetString("max-age")
	// if maxAge != "" {
	// 	sess.Config.Global.MaxAge = maxAge
	// }
	//
	// disableCache, _ := cmd.Flags().GetBool("disable-cache")
	// if disableCache {
	// 	sess.Config.Global.DisableCache = disableCache
	// }
	//
	// output, _ := cmd.Flags().GetString("output")
	// if output != "" {
	// 	sess.Config.Global.Output = output
	// }
	//
	// maxValueChars, _ := cmd.Flags().GetInt32("max-value-chars")
	// if maxValueChars > 0 {
	// 	sess.Config.Global.MaxValueChars = maxValueChars
	// }

	sess.Config.Global.IndentSpaces = c.DefaultIndentSpaces

	// default to config global style
	sess.Config.Global.Style = v.GetString("global.style")

	// override with cli flag if set
	// outputStyle, _ := cmd.Flags().GetString("style")
	// if outputStyle != "" {
	// 	sess.Config.Global.Style = outputStyle
	// }

	return sess, nil
}

var ProgramLevel = new(slog.LevelVar) // Info by default

func initLogging(logLevel string) error {
	hOptions := slog.HandlerOptions{AddSource: false}

	sess.Config.Global.LogLevel = logLevel

	// set log level
	switch strings.ToUpper(logLevel) {
	case "ERROR":
		ProgramLevel.Set(slog.LevelError)

		sess.HideProgress = false
	case "WARN":
		ProgramLevel.Set(slog.LevelWarn)

		sess.HideProgress = false
	case "INFO":
		ProgramLevel.Set(slog.LevelInfo)

		sess.HideProgress = true
	case "DEBUG":
		ProgramLevel.Set(slog.LevelDebug)

		sess.HideProgress = true
	default:
		// match the CLI's default log level
		ProgramLevel.Set(slog.LevelWarn)

		sess.HideProgress = false
	}

	hOptions.Level = ProgramLevel

	// Open log file for session logger
	logFile, err := os.OpenFile(LogFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, LogFilePerms)
	if err != nil {
		return fmt.Errorf("failed to open log file for session logger: %w", err)
	}

	sess.Logger = slog.New(slog.NewTextHandler(logFile, &hOptions))

	return nil
}

func setProviderAPIKey(v *viper.Viper, envKey string, apiKey *string, enabled **bool) {
	if *apiKey == "" {
		*apiKey = v.GetString(envKey)
	}

	if *apiKey == "" {
		*enabled = ToPtr(false)
	}
}

func readProviderAuthKeys(v *viper.Viper) {
	// read provider auth keys from env if not set in session
	setProviderAPIKey(v, "abuseipdb_api_key", &sess.Providers.AbuseIPDB.APIKey, &sess.Providers.AbuseIPDB.Enabled)
	setProviderAPIKey(v, "criminal_ip_api_key", &sess.Providers.CriminalIP.APIKey, &sess.Providers.CriminalIP.Enabled)
	setProviderAPIKey(v, "ipqs_api_key", &sess.Providers.IPQS.APIKey, &sess.Providers.IPQS.Enabled)
	setProviderAPIKey(v, "shodan_api_key", &sess.Providers.Shodan.APIKey, &sess.Providers.Shodan.Enabled)
	setProviderAPIKey(v, "virustotal_api_key", &sess.Providers.VirusTotal.APIKey, &sess.Providers.VirusTotal.Enabled)
}
