package config

import (
	"fmt"
	"os"
	"strings"

	c "github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/registry"
	"github.com/jonhadfield/ipscout/session"
	"github.com/spf13/viper"
)

func ToPtr[T any](v T) *T {
	return &v
}

// UpdateConfigFile brings the user's config file at configPath up to date:
// it adds providers introduced since the file was written and, once, disables
// keyed providers that have no API key. Changes and failures are reported as
// session warnings rather than stopping the run.
func UpdateConfigFile(sess *session.Session, configPath string) {
	if _, err := registry.EnsureDefaultProvidersInConfig(configPath); err != nil {
		sess.Messages.AddWarn(fmt.Sprintf(c.MsgConfigUpdateFailedFmt, err))
	}

	disabled, err := registry.DisableKeylessProvidersInConfig(configPath, os.Getenv)
	if err != nil {
		sess.Messages.AddWarn(fmt.Sprintf(c.MsgConfigUpdateFailedFmt, err))

		return
	}

	if len(disabled) > 0 {
		sess.Messages.AddWarn(fmt.Sprintf(c.MsgKeylessDisabledFmt, strings.Join(disabled, ", ")))
	}
}

// ReportMissingAPIKeys adds an error message for every keyed provider that is
// enabled without an API key. Call it once provider config and keys from the
// environment have both been read.
func ReportMissingAPIKeys(sess *session.Session) {
	if sess.UseTestData {
		return
	}

	for _, e := range registry.EnabledWithoutKey(*sess) {
		sess.Messages.AddError(fmt.Sprintf(c.MsgMissingAPIKeyFmt, e.DisplayName, e.KeyEnv, strings.ToLower(e.Name)))
	}
}

// Output priority defaults mirror the constants package so the CLI and TUI
// order results identically; see constants.Default*OutputPriority.
const (
	defaultAbuseIPDBOutputPriority    = c.DefaultAbuseIPDBOutputPriority
	defaultAlibabaOutputPriority      = c.DefaultAlibabaOutputPriority
	defaultAnnotatedOutputPriority    = c.DefaultAnnotatedOutputPriority
	defaultAWSOutputPriority          = c.DefaultAWSOutputPriority
	defaultAzureOutputPriority        = c.DefaultAzureOutputPriority
	defaultAzureWAFOutputPriority     = c.DefaultAzureWAFOutputPriority
	defaultBingbotOutputPriority      = c.DefaultBingbotOutputPriority
	defaultCriminalIPOutputPriority   = c.DefaultCriminalIPOutputPriority
	defaultDigitalOceanOutputPriority = c.DefaultDigitalOceanOutputPriority
	defaultGCPOutputPriority          = c.DefaultGCPOutputPriority
	defaultGoogleOutputPriority       = c.DefaultGoogleOutputPriority
	defaultGooglebotOutputPriority    = c.DefaultGooglebotOutputPriority
	defaultGoogleSCOutputPriority     = c.DefaultGoogleSCOutputPriority
	defaultHetznerOutputPriority      = c.DefaultHetznerOutputPriority
	defaultiCloudPROutputPriority     = c.DefaultiCloudPROutputPriority
	defaultIPAPIOutputPriority        = c.DefaultIPAPIOutputPriority
	defaultIPQSOutputPriority         = c.DefaultIPQSOutputPriority
	defaultIPURLOutputPriority        = c.DefaultIPURLOutputPriority
	defaultLinodeOutputPriority       = c.DefaultLinodeOutputPriority
	defaultPtrOutputPriority          = c.DefaultPtrOutputPriority
	defaultScalewayOutputPriority     = c.DefaultScalewayOutputPriority
	defaultShodanOutputPriority       = c.DefaultShodanOutputPriority
	defaultVirusTotalOutputPriority   = c.DefaultVirusTotalOutputPriority
	defaultVultrOutputPriority        = c.DefaultVultrOutputPriority
	defaultZscalerOutputPriority      = c.DefaultZscalerOutputPriority
)

func InitProviders(sess *session.Session, v *viper.Viper) {
	// providers requiring no configuration default to enabled when absent
	// from the user's config file
	registry.SetEnabledDefaults(v)

	// IP API
	if v.IsSet("providers.ipapi.api_key") {
		sess.Providers.IPAPI.APIKey = v.GetString("providers.ipapi.api_key")
	}

	sess.Providers.IPAPI.ResultCacheTTL = v.GetInt64("providers.ipapi.result_cache_ttl")

	// Abuse IPDB
	if v.IsSet("providers.abuseipdb.enabled") {
		sess.Providers.AbuseIPDB.Enabled = ToPtr(v.GetBool("providers.abuseipdb.enabled"))
	}

	if v.IsSet("providers.abuseipdb.output_priority") {
		sess.Providers.AbuseIPDB.OutputPriority = ToPtr(v.GetInt32("providers.abuseipdb.output_priority"))
	} else {
		sess.Providers.AbuseIPDB.OutputPriority = ToPtr(int32(defaultAbuseIPDBOutputPriority))
	}

	sess.Providers.AbuseIPDB.MaxAge = v.GetInt("providers.abuseipdb.max_age")
	sess.Providers.AbuseIPDB.ResultCacheTTL = v.GetInt64("providers.abuseipdb.result_cache_ttl")

	// Alibaba
	if v.IsSet("providers.alibaba.enabled") {
		sess.Providers.Alibaba.Enabled = ToPtr(v.GetBool("providers.alibaba.enabled"))
	}

	if v.IsSet("providers.alibaba.output_priority") {
		sess.Providers.Alibaba.OutputPriority = ToPtr(v.GetInt32("providers.alibaba.output_priority"))
	} else {
		sess.Providers.Alibaba.OutputPriority = ToPtr(int32(defaultAlibabaOutputPriority))
	}

	sess.Providers.Alibaba.URL = v.GetString("providers.alibaba.url")
	sess.Providers.Alibaba.DocumentCacheTTL = v.GetInt64("providers.alibaba.document_cache_ttl")

	if v.IsSet("providers.annotated.enabled") {
		sess.Providers.Annotated.Enabled = ToPtr(v.GetBool("providers.annotated.enabled"))
	}

	if v.IsSet("providers.annotated.output_priority") {
		sess.Providers.Annotated.OutputPriority = ToPtr(v.GetInt32("providers.annotated.output_priority"))
	} else {
		sess.Providers.Annotated.OutputPriority = ToPtr(int32(defaultAnnotatedOutputPriority))
	}

	sess.Providers.Annotated.Paths = v.GetStringSlice("providers.annotated.paths")
	sess.Providers.Annotated.DocumentCacheTTL = v.GetInt64("providers.annotated.document_cache_ttl")

	if v.IsSet("providers.aws.enabled") {
		sess.Providers.AWS.Enabled = ToPtr(v.GetBool("providers.aws.enabled"))
	}

	if v.IsSet("providers.aws.output_priority") {
		sess.Providers.AWS.OutputPriority = ToPtr(v.GetInt32("providers.aws.output_priority"))
	} else {
		sess.Providers.AWS.OutputPriority = ToPtr(int32(defaultAWSOutputPriority))
	}

	sess.Providers.AWS.URL = v.GetString("providers.aws.url")
	sess.Providers.AWS.DocumentCacheTTL = v.GetInt64("providers.aws.document_cache_ttl")

	// Azure
	if v.IsSet("providers.azure.enabled") {
		sess.Providers.Azure.Enabled = ToPtr(v.GetBool("providers.azure.enabled"))
	}

	if v.IsSet("providers.azure.output_priority") {
		sess.Providers.Azure.OutputPriority = ToPtr(v.GetInt32("providers.azure.output_priority"))
	} else {
		sess.Providers.Azure.OutputPriority = ToPtr(int32(defaultAzureOutputPriority))
	}

	sess.Providers.Azure.URL = v.GetString("providers.azure.url")

	sess.Providers.Azure.DocumentCacheTTL = v.GetInt64("providers.azure.document_cache_ttl")

	// AzureWAF
	if v.IsSet("providers.azurewaf.enabled") {
		sess.Providers.AzureWAF.Enabled = ToPtr(v.GetBool("providers.azurewaf.enabled"))
	}

	if v.IsSet("providers.azurewaf.output_priority") {
		sess.Providers.AzureWAF.OutputPriority = ToPtr(v.GetInt32("providers.azurewaf.output_priority"))
	} else {
		sess.Providers.AzureWAF.OutputPriority = ToPtr(int32(defaultAzureWAFOutputPriority))
	}

	sess.Providers.AzureWAF.ResourceIDs = v.GetStringSlice("providers.azurewaf.resource_ids")

	sess.Providers.AzureWAF.DocumentCacheTTL = v.GetInt64("providers.azurewaf.document_cache_ttl")

	// CriminalIP
	if v.IsSet("providers.criminalip.enabled") {
		sess.Providers.CriminalIP.Enabled = ToPtr(v.GetBool("providers.criminalip.enabled"))
	}

	if v.IsSet("providers.criminalip.output_priority") {
		sess.Providers.CriminalIP.OutputPriority = ToPtr(v.GetInt32("providers.criminalip.output_priority"))
	} else {
		sess.Providers.CriminalIP.OutputPriority = ToPtr(int32(defaultCriminalIPOutputPriority))
	}

	sess.Providers.CriminalIP.ResultCacheTTL = v.GetInt64("providers.criminalip.result_cache_ttl")

	// BingBot
	if v.IsSet("providers.bingbot.enabled") {
		sess.Providers.Bingbot.Enabled = ToPtr(v.GetBool("providers.bingbot.enabled"))
	}

	if v.IsSet("providers.bingbot.output_priority") {
		sess.Providers.Bingbot.OutputPriority = ToPtr(v.GetInt32("providers.bingbot.output_priority"))
	} else {
		sess.Providers.Bingbot.OutputPriority = ToPtr(int32(defaultBingbotOutputPriority))
	}

	sess.Providers.Bingbot.URL = v.GetString("providers.bingbot.url")

	sess.Providers.Bingbot.DocumentCacheTTL = v.GetInt64("providers.bingbot.document_cache_ttl")

	// DigitalOcean
	if v.IsSet("providers.digitalocean.enabled") {
		sess.Providers.DigitalOcean.Enabled = ToPtr(v.GetBool("providers.digitalocean.enabled"))
	}

	if v.IsSet("providers.digitalocean.output_priority") {
		sess.Providers.DigitalOcean.OutputPriority = ToPtr(v.GetInt32("providers.digitalocean.output_priority"))
	} else {
		sess.Providers.DigitalOcean.OutputPriority = ToPtr(int32(defaultDigitalOceanOutputPriority))
	}

	sess.Providers.DigitalOcean.URL = v.GetString("providers.digitalocean.url")
	sess.Providers.DigitalOcean.DocumentCacheTTL = v.GetInt64("providers.digitalocean.document_cache_ttl")

	// GCP
	if v.IsSet("providers.gcp.enabled") {
		sess.Providers.GCP.Enabled = ToPtr(v.GetBool("providers.gcp.enabled"))
	}

	if v.IsSet("providers.gcp.output_priority") {
		sess.Providers.GCP.OutputPriority = ToPtr(v.GetInt32("providers.gcp.output_priority"))
	} else {
		sess.Providers.GCP.OutputPriority = ToPtr(int32(defaultGCPOutputPriority))
	}

	sess.Providers.GCP.URL = v.GetString("providers.gcp.url")
	sess.Providers.GCP.DocumentCacheTTL = v.GetInt64("providers.gcp.document_cache_ttl")

	// Google
	if v.IsSet("providers.google.enabled") {
		sess.Providers.Google.Enabled = ToPtr(v.GetBool("providers.google.enabled"))
	}

	if v.IsSet("providers.google.output_priority") {
		sess.Providers.Google.OutputPriority = ToPtr(v.GetInt32("providers.google.output_priority"))
	} else {
		sess.Providers.Google.OutputPriority = ToPtr(int32(defaultGoogleOutputPriority))
	}

	// Googlebot
	if v.IsSet("providers.googlebot.enabled") {
		sess.Providers.Googlebot.Enabled = ToPtr(v.GetBool("providers.googlebot.enabled"))
	}

	if v.IsSet("providers.googlebot.output_priority") {
		sess.Providers.Googlebot.OutputPriority = ToPtr(v.GetInt32("providers.googlebot.output_priority"))
	} else {
		sess.Providers.Googlebot.OutputPriority = ToPtr(int32(defaultGooglebotOutputPriority))
	}

	sess.Providers.Googlebot.URL = v.GetString("providers.googlebot.url")

	// GoogleSC
	if v.IsSet("providers.googlesc.enabled") {
		sess.Providers.GoogleSC.Enabled = ToPtr(v.GetBool("providers.googlesc.enabled"))
	}

	if v.IsSet("providers.googlesc.output_priority") {
		sess.Providers.GoogleSC.OutputPriority = ToPtr(v.GetInt32("providers.googlesc.output_priority"))
	} else {
		sess.Providers.GoogleSC.OutputPriority = ToPtr(int32(defaultGoogleSCOutputPriority))
	}

	sess.Providers.GoogleSC.URL = v.GetString("providers.googlesc.url")

	// Hetzner
	if v.IsSet("providers.hetzner.enabled") {
		sess.Providers.Hetzner.Enabled = ToPtr(v.GetBool("providers.hetzner.enabled"))
	}

	if v.IsSet("providers.hetzner.output_priority") {
		sess.Providers.Hetzner.OutputPriority = ToPtr(v.GetInt32("providers.hetzner.output_priority"))
	} else {
		sess.Providers.Hetzner.OutputPriority = ToPtr(int32(defaultHetznerOutputPriority))
	}

	// iCloud Private Relay
	if v.IsSet("providers.icloudpr.enabled") {
		sess.Providers.ICloudPR.Enabled = ToPtr(v.GetBool("providers.icloudpr.enabled"))
	}

	if v.IsSet("providers.icloudpr.output_priority") {
		sess.Providers.ICloudPR.OutputPriority = ToPtr(v.GetInt32("providers.icloudpr.output_priority"))
	} else {
		sess.Providers.ICloudPR.OutputPriority = ToPtr(int32(defaultiCloudPROutputPriority))
	}

	sess.Providers.ICloudPR.URL = v.GetString("providers.icloudpr.url")
	sess.Providers.ICloudPR.DocumentCacheTTL = v.GetInt64("providers.icloudpr.document_cache_ttl")

	// IPQS
	if v.IsSet("providers.ipqs.enabled") {
		sess.Providers.IPQS.Enabled = ToPtr(v.GetBool("providers.ipqs.enabled"))
	}

	if v.IsSet("providers.ipqs.output_priority") {
		sess.Providers.IPQS.OutputPriority = ToPtr(v.GetInt32("providers.ipqs.output_priority"))
	} else {
		sess.Providers.IPQS.OutputPriority = ToPtr(int32(defaultIPQSOutputPriority))
	}

	if v.IsSet("providers.ipqs.api_key") {
		sess.Providers.IPQS.APIKey = v.GetString("providers.ipqs.api_key")
	}

	sess.Providers.IPQS.ResultCacheTTL = v.GetInt64("providers.ipqs.result_cache_ttl")

	// IP URL
	if v.IsSet("providers.ipurl.enabled") {
		sess.Providers.IPURL.Enabled = ToPtr(v.GetBool("providers.ipurl.enabled"))
	}

	if v.IsSet("providers.ipurl.output_priority") {
		sess.Providers.IPURL.OutputPriority = ToPtr(v.GetInt32("providers.ipurl.output_priority"))
	} else {
		sess.Providers.IPURL.OutputPriority = ToPtr(int32(defaultIPURLOutputPriority))
	}

	sess.Providers.IPURL.URLs = v.GetStringSlice("providers.ipurl.urls")
	sess.Providers.IPURL.DocumentCacheTTL = v.GetInt64("providers.ipurl.document_cache_ttl")

	// Linode
	if v.IsSet("providers.linode.enabled") {
		sess.Providers.Linode.Enabled = ToPtr(v.GetBool("providers.linode.enabled"))
	}

	if v.IsSet("providers.linode.output_priority") {
		sess.Providers.Linode.OutputPriority = ToPtr(v.GetInt32("providers.linode.output_priority"))
	} else {
		sess.Providers.Linode.OutputPriority = ToPtr(int32(defaultLinodeOutputPriority))
	}

	sess.Providers.Linode.DocumentCacheTTL = v.GetInt64("providers.linode.document_cache_ttl")
	sess.Providers.Linode.URL = v.GetString("providers.linode.url")
	sess.Providers.Shodan.ResultCacheTTL = v.GetInt64("providers.shodan.result_cache_ttl")

	// M247
	if v.IsSet("providers.m247.enabled") {
		sess.Providers.M247.Enabled = ToPtr(v.GetBool("providers.m247.enabled"))
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
	sess.Providers.OpenAI.AdsBotURL = v.GetString("providers.openai.adsbot_url")

	// OVH
	if v.IsSet("providers.ovh.enabled") {
		sess.Providers.OVH.Enabled = ToPtr(v.GetBool("providers.ovh.enabled"))
	}

	if v.IsSet("providers.ovh.output_priority") {
		sess.Providers.OVH.OutputPriority = ToPtr(v.GetInt32("providers.ovh.output_priority"))
	} else {
		sess.Providers.OVH.OutputPriority = ToPtr(int32(c.DefaultOVHOutputPriority))
	}

	sess.Providers.OVH.DocumentCacheTTL = v.GetInt64("providers.ovh.document_cache_ttl")
	sess.Providers.OVH.URL = v.GetString("providers.ovh.url")

	// Scaleway
	if v.IsSet("providers.scaleway.enabled") {
		sess.Providers.Scaleway.Enabled = ToPtr(v.GetBool("providers.scaleway.enabled"))
	}

	if v.IsSet("providers.scaleway.output_priority") {
		sess.Providers.Scaleway.OutputPriority = ToPtr(v.GetInt32("providers.scaleway.output_priority"))
	} else {
		sess.Providers.Scaleway.OutputPriority = ToPtr(int32(defaultScalewayOutputPriority))
	}

	sess.Providers.Scaleway.URL = v.GetString("providers.scaleway.url")
	sess.Providers.Scaleway.DocumentCacheTTL = v.GetInt64("providers.scaleway.document_cache_ttl")

	sess.Providers.Shodan.ResultCacheTTL = v.GetInt64("providers.shodan.result_cache_ttl")

	// Shodan
	if v.IsSet("providers.shodan.enabled") {
		sess.Providers.Shodan.Enabled = ToPtr(v.GetBool("providers.shodan.enabled"))
	}

	if v.IsSet("providers.shodan.output_priority") {
		sess.Providers.Shodan.OutputPriority = ToPtr(v.GetInt32("providers.shodan.output_priority"))
	} else {
		sess.Providers.Shodan.OutputPriority = ToPtr(int32(defaultShodanOutputPriority))
	}

	if v.IsSet("providers.shodan.api_key") {
		sess.Providers.Shodan.APIKey = v.GetString("providers.shodan.api_key")
	}

	// PTR
	if v.IsSet("providers.ptr.enabled") {
		sess.Providers.PTR.Enabled = ToPtr(v.GetBool("providers.ptr.enabled"))
	}

	if v.IsSet("providers.ptr.output_priority") {
		sess.Providers.PTR.OutputPriority = ToPtr(v.GetInt32("providers.ptr.output_priority"))
	} else {
		sess.Providers.PTR.OutputPriority = ToPtr(int32(defaultPtrOutputPriority))
	}

	sess.Providers.PTR.ResultCacheTTL = v.GetInt64("providers.ptr.result_cache_ttl")
	sess.Providers.PTR.Nameservers = v.GetStringSlice("providers.ptr.nameservers")

	// IPAPI
	if v.IsSet("providers.ipapi.enabled") {
		sess.Providers.IPAPI.Enabled = ToPtr(v.GetBool("providers.ipapi.enabled"))
	}

	if v.IsSet("providers.ipapi.output_priority") {
		sess.Providers.IPAPI.OutputPriority = ToPtr(v.GetInt32("providers.ipapi.output_priority"))
	} else {
		sess.Providers.IPAPI.OutputPriority = ToPtr(int32(defaultIPAPIOutputPriority))
	}

	// ip-api.com
	if v.IsSet("providers.ipapicom.enabled") {
		sess.Providers.IPAPICom.Enabled = ToPtr(v.GetBool("providers.ipapicom.enabled"))
	}

	if v.IsSet("providers.ipapicom.output_priority") {
		sess.Providers.IPAPICom.OutputPriority = ToPtr(v.GetInt32("providers.ipapicom.output_priority"))
	} else {
		sess.Providers.IPAPICom.OutputPriority = ToPtr(int32(c.DefaultIPAPIComOutputPriority))
	}

	sess.Providers.IPAPICom.ResultCacheTTL = v.GetInt64("providers.ipapicom.result_cache_ttl")

	// InternetDB
	if v.IsSet("providers.internetdb.enabled") {
		sess.Providers.InternetDB.Enabled = ToPtr(v.GetBool("providers.internetdb.enabled"))
	}

	if v.IsSet("providers.internetdb.output_priority") {
		sess.Providers.InternetDB.OutputPriority = ToPtr(v.GetInt32("providers.internetdb.output_priority"))
	} else {
		sess.Providers.InternetDB.OutputPriority = ToPtr(int32(c.DefaultInternetDBOutputPriority))
	}

	sess.Providers.InternetDB.ResultCacheTTL = v.GetInt64("providers.internetdb.result_cache_ttl")

	// IPtoASN
	if v.IsSet("providers.iptoasn.enabled") {
		sess.Providers.IPToASN.Enabled = ToPtr(v.GetBool("providers.iptoasn.enabled"))
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
	}

	if v.IsSet("providers.virustotal.output_priority") {
		sess.Providers.VirusTotal.OutputPriority = ToPtr(v.GetInt32("providers.virustotal.output_priority"))
	} else {
		sess.Providers.VirusTotal.OutputPriority = ToPtr(int32(defaultVirusTotalOutputPriority))
	}

	// Vultr
	if v.IsSet("providers.vultr.enabled") {
		sess.Providers.Vultr.Enabled = ToPtr(v.GetBool("providers.vultr.enabled"))
	}

	if v.IsSet("providers.vultr.output_priority") {
		sess.Providers.Vultr.OutputPriority = ToPtr(v.GetInt32("providers.vultr.output_priority"))
	} else {
		sess.Providers.Vultr.OutputPriority = ToPtr(int32(defaultVultrOutputPriority))
	}

	sess.Providers.Vultr.URL = v.GetString("providers.vultr.url")
	sess.Providers.Vultr.DocumentCacheTTL = v.GetInt64("providers.vultr.document_cache_ttl")

	// Zscaler
	if v.IsSet("providers.zscaler.enabled") {
		sess.Providers.Zscaler.Enabled = ToPtr(v.GetBool("providers.zscaler.enabled"))
	}

	if v.IsSet("providers.zscaler.output_priority") {
		sess.Providers.Zscaler.OutputPriority = ToPtr(v.GetInt32("providers.zscaler.output_priority"))
	} else {
		sess.Providers.Zscaler.OutputPriority = ToPtr(int32(defaultZscalerOutputPriority))
	}

	sess.Providers.Zscaler.DocumentCacheTTL = v.GetInt64("providers.zscaler.document_cache_ttl")
	sess.Providers.Zscaler.URL = v.GetString("providers.zscaler.url")

	initSimpleProviderConfig(v, "ahrefs", c.DefaultAhrefsOutputPriority,
		&sess.Providers.Ahrefs.Enabled, &sess.Providers.Ahrefs.OutputPriority, &sess.Providers.Ahrefs.DocumentCacheTTL)
	initSimpleProviderConfig(v, "akamai", c.DefaultAkamaiOutputPriority,
		&sess.Providers.Akamai.Enabled, &sess.Providers.Akamai.OutputPriority, &sess.Providers.Akamai.DocumentCacheTTL)
	initSimpleProviderConfig(v, "anthropic", c.DefaultAnthropicOutputPriority,
		&sess.Providers.Anthropic.Enabled, &sess.Providers.Anthropic.OutputPriority, &sess.Providers.Anthropic.DocumentCacheTTL)
	initSimpleProviderConfig(v, "applebot", c.DefaultApplebotOutputPriority,
		&sess.Providers.Applebot.Enabled, &sess.Providers.Applebot.OutputPriority, &sess.Providers.Applebot.DocumentCacheTTL)
	initSimpleProviderConfig(v, "atlassian", c.DefaultAtlassianOutputPriority,
		&sess.Providers.Atlassian.Enabled, &sess.Providers.Atlassian.OutputPriority, &sess.Providers.Atlassian.DocumentCacheTTL)
	initSimpleProviderConfig(v, "blocklistde", c.DefaultBlocklistDEOutputPriority,
		&sess.Providers.BlocklistDE.Enabled, &sess.Providers.BlocklistDE.OutputPriority, &sess.Providers.BlocklistDE.DocumentCacheTTL)
	initSimpleProviderConfig(v, "bunny", c.DefaultBunnyOutputPriority,
		&sess.Providers.Bunny.Enabled, &sess.Providers.Bunny.OutputPriority, &sess.Providers.Bunny.DocumentCacheTTL)
	initSimpleProviderConfig(v, "cdn77", c.DefaultCDN77OutputPriority,
		&sess.Providers.CDN77.Enabled, &sess.Providers.CDN77.OutputPriority, &sess.Providers.CDN77.DocumentCacheTTL)
	initSimpleProviderConfig(v, "cinsscore", c.DefaultCINSScoreOutputPriority,
		&sess.Providers.CINSScore.Enabled, &sess.Providers.CINSScore.OutputPriority, &sess.Providers.CINSScore.DocumentCacheTTL)
	initSimpleProviderConfig(v, "cloudflare", c.DefaultCloudflareOutputPriority,
		&sess.Providers.Cloudflare.Enabled, &sess.Providers.Cloudflare.OutputPriority, &sess.Providers.Cloudflare.DocumentCacheTTL)
	initSimpleProviderConfig(v, "contabo", c.DefaultContaboOutputPriority,
		&sess.Providers.Contabo.Enabled, &sess.Providers.Contabo.OutputPriority, &sess.Providers.Contabo.DocumentCacheTTL)
	initSimpleProviderConfig(v, "datadog", c.DefaultDatadogOutputPriority,
		&sess.Providers.Datadog.Enabled, &sess.Providers.Datadog.OutputPriority, &sess.Providers.Datadog.DocumentCacheTTL)
	initSimpleProviderConfig(v, "dshield", c.DefaultDShieldOutputPriority,
		&sess.Providers.DShield.Enabled, &sess.Providers.DShield.OutputPriority, &sess.Providers.DShield.DocumentCacheTTL)
	initSimpleProviderConfig(v, "duckduckbot", c.DefaultDuckDuckBotOutputPriority,
		&sess.Providers.DuckDuckBot.Enabled, &sess.Providers.DuckDuckBot.OutputPriority, &sess.Providers.DuckDuckBot.DocumentCacheTTL)
	initSimpleProviderConfig(v, "emergingthreats", c.DefaultEmergingThreatsOutputPriority,
		&sess.Providers.EmergingThreats.Enabled, &sess.Providers.EmergingThreats.OutputPriority, &sess.Providers.EmergingThreats.DocumentCacheTTL)
	initSimpleProviderConfig(v, "fastly", c.DefaultFastlyOutputPriority,
		&sess.Providers.Fastly.Enabled, &sess.Providers.Fastly.OutputPriority, &sess.Providers.Fastly.DocumentCacheTTL)
	initSimpleProviderConfig(v, "flyio", c.DefaultFlyioOutputPriority,
		&sess.Providers.Flyio.Enabled, &sess.Providers.Flyio.OutputPriority, &sess.Providers.Flyio.DocumentCacheTTL)
	initSimpleProviderConfig(v, "github", c.DefaultGitHubOutputPriority,
		&sess.Providers.GitHub.Enabled, &sess.Providers.GitHub.OutputPriority, &sess.Providers.GitHub.DocumentCacheTTL)
	initSimpleProviderConfig(v, "googleutf", c.DefaultGoogleUTFOutputPriority,
		&sess.Providers.GoogleUTF.Enabled, &sess.Providers.GoogleUTF.OutputPriority, &sess.Providers.GoogleUTF.DocumentCacheTTL)
	initSimpleProviderConfig(v, "ibmcloud", c.DefaultIBMCloudOutputPriority,
		&sess.Providers.IBMCloud.Enabled, &sess.Providers.IBMCloud.OutputPriority, &sess.Providers.IBMCloud.DocumentCacheTTL)
	initSimpleProviderConfig(v, "imperva", c.DefaultImpervaOutputPriority,
		&sess.Providers.Imperva.Enabled, &sess.Providers.Imperva.OutputPriority, &sess.Providers.Imperva.DocumentCacheTTL)
	initSimpleProviderConfig(v, "leaseweb", c.DefaultLeasewebOutputPriority,
		&sess.Providers.Leaseweb.Enabled, &sess.Providers.Leaseweb.OutputPriority, &sess.Providers.Leaseweb.DocumentCacheTTL)
	initSimpleProviderConfig(v, "oci", c.DefaultOCIOutputPriority,
		&sess.Providers.OCI.Enabled, &sess.Providers.OCI.OutputPriority, &sess.Providers.OCI.DocumentCacheTTL)
	initSimpleProviderConfig(v, "perplexitybot", c.DefaultPerplexityBotOutputPriority,
		&sess.Providers.PerplexityBot.Enabled, &sess.Providers.PerplexityBot.OutputPriority, &sess.Providers.PerplexityBot.DocumentCacheTTL)
	initSimpleProviderConfig(v, "render", c.DefaultRenderOutputPriority,
		&sess.Providers.Render.Enabled, &sess.Providers.Render.OutputPriority, &sess.Providers.Render.DocumentCacheTTL)
	initSimpleProviderConfig(v, "spamhaus", c.DefaultSpamhausOutputPriority,
		&sess.Providers.Spamhaus.Enabled, &sess.Providers.Spamhaus.OutputPriority, &sess.Providers.Spamhaus.DocumentCacheTTL)
	initSimpleProviderConfig(v, "stripe", c.DefaultStripeOutputPriority,
		&sess.Providers.Stripe.Enabled, &sess.Providers.Stripe.OutputPriority, &sess.Providers.Stripe.DocumentCacheTTL)
	initSimpleProviderConfig(v, "tencent", c.DefaultTencentOutputPriority,
		&sess.Providers.Tencent.Enabled, &sess.Providers.Tencent.OutputPriority, &sess.Providers.Tencent.DocumentCacheTTL)
	initSimpleProviderConfig(v, "uptimerobot", c.DefaultUptimeRobotOutputPriority,
		&sess.Providers.UptimeRobot.Enabled, &sess.Providers.UptimeRobot.OutputPriority, &sess.Providers.UptimeRobot.DocumentCacheTTL)
	initSimpleProviderConfig(v, "cymru", c.DefaultCymruOutputPriority,
		&sess.Providers.Cymru.Enabled, &sess.Providers.Cymru.OutputPriority, &sess.Providers.Cymru.DocumentCacheTTL)
	initSimpleProviderConfig(v, "greensnow", c.DefaultGreenSnowOutputPriority,
		&sess.Providers.GreenSnow.Enabled, &sess.Providers.GreenSnow.OutputPriority, &sess.Providers.GreenSnow.DocumentCacheTTL)
	initSimpleProviderConfig(v, "betterstack", c.DefaultBetterStackOutputPriority,
		&sess.Providers.BetterStack.Enabled, &sess.Providers.BetterStack.OutputPriority, &sess.Providers.BetterStack.DocumentCacheTTL)
	initSimpleProviderConfig(v, "checkly", c.DefaultChecklyOutputPriority,
		&sess.Providers.Checkly.Enabled, &sess.Providers.Checkly.OutputPriority, &sess.Providers.Checkly.DocumentCacheTTL)
	initSimpleProviderConfig(v, "feodo", c.DefaultFeodoOutputPriority,
		&sess.Providers.Feodo.Enabled, &sess.Providers.Feodo.OutputPriority, &sess.Providers.Feodo.DocumentCacheTTL)
	initSimpleProviderConfig(v, "tor", c.DefaultTorOutputPriority,
		&sess.Providers.Tor.Enabled, &sess.Providers.Tor.OutputPriority, &sess.Providers.Tor.DocumentCacheTTL)
	initSimpleProviderConfig(v, "m365", c.DefaultM365OutputPriority,
		&sess.Providers.M365.Enabled, &sess.Providers.M365.OutputPriority, &sess.Providers.M365.DocumentCacheTTL)
	initSimpleProviderConfig(v, "okta", c.DefaultOktaOutputPriority,
		&sess.Providers.Okta.Enabled, &sess.Providers.Okta.OutputPriority, &sess.Providers.Okta.DocumentCacheTTL)
	initSimpleProviderConfig(v, "grafana", c.DefaultGrafanaOutputPriority,
		&sess.Providers.Grafana.Enabled, &sess.Providers.Grafana.OutputPriority, &sess.Providers.Grafana.DocumentCacheTTL)
	initSimpleProviderConfig(v, "sentry", c.DefaultSentryOutputPriority,
		&sess.Providers.Sentry.Enabled, &sess.Providers.Sentry.OutputPriority, &sess.Providers.Sentry.DocumentCacheTTL)
	initSimpleProviderConfig(v, "site24x7", c.DefaultSite24x7OutputPriority,
		&sess.Providers.Site24x7.Enabled, &sess.Providers.Site24x7.OutputPriority, &sess.Providers.Site24x7.DocumentCacheTTL)
	initSimpleProviderConfig(v, "updown", c.DefaultUpdownOutputPriority,
		&sess.Providers.Updown.Enabled, &sess.Providers.Updown.OutputPriority, &sess.Providers.Updown.DocumentCacheTTL)
	initSimpleProviderConfig(v, "uptrends", c.DefaultUptrendsOutputPriority,
		&sess.Providers.Uptrends.Enabled, &sess.Providers.Uptrends.OutputPriority, &sess.Providers.Uptrends.DocumentCacheTTL)
	initSimpleProviderConfig(v, "detectify", c.DefaultDetectifyOutputPriority,
		&sess.Providers.Detectify.Enabled, &sess.Providers.Detectify.OutputPriority, &sess.Providers.Detectify.DocumentCacheTTL)
	initSimpleProviderConfig(v, "tenable", c.DefaultTenableOutputPriority,
		&sess.Providers.Tenable.Enabled, &sess.Providers.Tenable.OutputPriority, &sess.Providers.Tenable.DocumentCacheTTL)
	initSimpleProviderConfig(v, "gcore", c.DefaultGcoreOutputPriority,
		&sess.Providers.Gcore.Enabled, &sess.Providers.Gcore.OutputPriority, &sess.Providers.Gcore.DocumentCacheTTL)
	initSimpleProviderConfig(v, "newrelic", c.DefaultNewRelicOutputPriority,
		&sess.Providers.NewRelic.Enabled, &sess.Providers.NewRelic.OutputPriority, &sess.Providers.NewRelic.DocumentCacheTTL)
	initSimpleProviderConfig(v, "pingdom", c.DefaultPingdomOutputPriority,
		&sess.Providers.Pingdom.Enabled, &sess.Providers.Pingdom.OutputPriority, &sess.Providers.Pingdom.DocumentCacheTTL)
	initSimpleProviderConfig(v, "statuscake", c.DefaultStatusCakeOutputPriority,
		&sess.Providers.StatusCake.Enabled, &sess.Providers.StatusCake.OutputPriority, &sess.Providers.StatusCake.DocumentCacheTTL)
	initSimpleProviderConfig(v, "zoom", c.DefaultZoomOutputPriority,
		&sess.Providers.Zoom.Enabled, &sess.Providers.Zoom.OutputPriority, &sess.Providers.Zoom.DocumentCacheTTL)
	initSimpleProviderConfig(v, "amazonbot", c.DefaultAmazonbotOutputPriority,
		&sess.Providers.Amazonbot.Enabled, &sess.Providers.Amazonbot.OutputPriority, &sess.Providers.Amazonbot.DocumentCacheTTL)
	initSimpleProviderConfig(v, "cachefly", c.DefaultCacheFlyOutputPriority,
		&sess.Providers.CacheFly.Enabled, &sess.Providers.CacheFly.OutputPriority, &sess.Providers.CacheFly.DocumentCacheTTL)
	initSimpleProviderConfig(v, "ccbot", c.DefaultCCBotOutputPriority,
		&sess.Providers.CCBot.Enabled, &sess.Providers.CCBot.OutputPriority, &sess.Providers.CCBot.DocumentCacheTTL)
	initSimpleProviderConfig(v, "gitlab", c.DefaultGitLabOutputPriority,
		&sess.Providers.GitLab.Enabled, &sess.Providers.GitLab.OutputPriority, &sess.Providers.GitLab.DocumentCacheTTL)
	initSimpleProviderConfig(v, "huawei", c.DefaultHuaweiOutputPriority,
		&sess.Providers.Huawei.Enabled, &sess.Providers.Huawei.OutputPriority, &sess.Providers.Huawei.DocumentCacheTTL)
	initSimpleProviderConfig(v, "intercom", c.DefaultIntercomOutputPriority,
		&sess.Providers.Intercom.Enabled, &sess.Providers.Intercom.OutputPriority, &sess.Providers.Intercom.DocumentCacheTTL)
	initSimpleProviderConfig(v, "hetrixtools", c.DefaultHetrixToolsOutputPriority,
		&sess.Providers.HetrixTools.Enabled, &sess.Providers.HetrixTools.OutputPriority, &sess.Providers.HetrixTools.DocumentCacheTTL)

	initSimpleProviderConfig(v, "nodeping", c.DefaultNodePingOutputPriority,
		&sess.Providers.NodePing.Enabled, &sess.Providers.NodePing.OutputPriority, &sess.Providers.NodePing.DocumentCacheTTL)

	initSimpleProviderConfig(v, "qualys", c.DefaultQualysOutputPriority,
		&sess.Providers.Qualys.Enabled, &sess.Providers.Qualys.OutputPriority, &sess.Providers.Qualys.DocumentCacheTTL)

	initSimpleProviderConfig(v, "asndrop", c.DefaultASNDropOutputPriority,
		&sess.Providers.ASNDrop.Enabled, &sess.Providers.ASNDrop.OutputPriority, &sess.Providers.ASNDrop.DocumentCacheTTL)

	initSimpleProviderConfig(v, "airvpn", c.DefaultAirVPNOutputPriority,
		&sess.Providers.AirVPN.Enabled, &sess.Providers.AirVPN.OutputPriority, &sess.Providers.AirVPN.DocumentCacheTTL)

	initSimpleProviderConfig(v, "ivpn", c.DefaultIVPNOutputPriority,
		&sess.Providers.IVPN.Enabled, &sess.Providers.IVPN.OutputPriority, &sess.Providers.IVPN.DocumentCacheTTL)

	initSimpleProviderConfig(v, "surfshark", c.DefaultSurfsharkOutputPriority,
		&sess.Providers.Surfshark.Enabled, &sess.Providers.Surfshark.OutputPriority, &sess.Providers.Surfshark.DocumentCacheTTL)

	initSimpleProviderConfig(v, "quiccloud", c.DefaultQuicCloudOutputPriority,
		&sess.Providers.QuicCloud.Enabled, &sess.Providers.QuicCloud.OutputPriority, &sess.Providers.QuicCloud.DocumentCacheTTL)

	initSimpleProviderConfig(v, "stopforumspam", c.DefaultStopForumSpamOutputPriority,
		&sess.Providers.StopForumSpam.Enabled, &sess.Providers.StopForumSpam.OutputPriority, &sess.Providers.StopForumSpam.DocumentCacheTTL)

	initSimpleProviderConfig(v, "binarydefense", c.DefaultBinaryDefenseOutputPriority,
		&sess.Providers.BinaryDefense.Enabled, &sess.Providers.BinaryDefense.OutputPriority, &sess.Providers.BinaryDefense.DocumentCacheTTL)

	initSimpleProviderConfig(v, "telegram", c.DefaultTelegramOutputPriority,
		&sess.Providers.Telegram.Enabled, &sess.Providers.Telegram.OutputPriority, &sess.Providers.Telegram.DocumentCacheTTL)

	initSimpleProviderConfig(v, "ipsum", c.DefaultIPsumOutputPriority,
		&sess.Providers.IPsum.Enabled, &sess.Providers.IPsum.OutputPriority, &sess.Providers.IPsum.DocumentCacheTTL)

	initSimpleProviderConfig(v, "x4bnet", c.DefaultX4BNetOutputPriority,
		&sess.Providers.X4BNet.Enabled, &sess.Providers.X4BNet.OutputPriority, &sess.Providers.X4BNet.DocumentCacheTTL)

	initSimpleProviderConfig(v, "circleci", c.DefaultCircleCIOutputPriority,
		&sess.Providers.CircleCI.Enabled, &sess.Providers.CircleCI.OutputPriority, &sess.Providers.CircleCI.DocumentCacheTTL)

	initSimpleProviderConfig(v, "threatfox", c.DefaultThreatFoxOutputPriority,
		&sess.Providers.ThreatFox.Enabled, &sess.Providers.ThreatFox.OutputPriority, &sess.Providers.ThreatFox.DocumentCacheTTL)

	initSimpleProviderConfig(v, "mullvad", c.DefaultMullvadOutputPriority,
		&sess.Providers.Mullvad.Enabled, &sess.Providers.Mullvad.OutputPriority, &sess.Providers.Mullvad.DocumentCacheTTL)
	initSimpleProviderConfig(v, "salesforce", c.DefaultSalesforceOutputPriority,
		&sess.Providers.Salesforce.Enabled, &sess.Providers.Salesforce.OutputPriority, &sess.Providers.Salesforce.DocumentCacheTTL)
}

// initSimpleProviderConfig wires a provider with the common enabled /
// output_priority / document_cache_ttl config shape into the session, so that
// providers registered in the registry are actually read from config.
func initSimpleProviderConfig(v *viper.Viper, key string, defaultPriority int32, enabled **bool, priority **int32, docCacheTTL *int64) {
	if v.IsSet("providers." + key + ".enabled") {
		*enabled = ToPtr(v.GetBool("providers." + key + ".enabled"))
	}

	if v.IsSet("providers." + key + ".output_priority") {
		*priority = ToPtr(v.GetInt32("providers." + key + ".output_priority"))
	} else {
		*priority = ToPtr(defaultPriority)
	}

	*docCacheTTL = v.GetInt64("providers." + key + ".document_cache_ttl")
}
