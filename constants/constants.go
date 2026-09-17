package constants

import "time"

const (
	AppName   = "ipscout"
	AppNameSC = "IPScout"

	ProviderNotDefinedFmt = "%s provider not defined in config"

	MsgInvalidHostFmt = "invalid host: %s"

	// MsgFetchFailedFmt reports, on a single line after the results, every
	// provider whose ip range data could not be fetched. The per-provider
	// errors are logged at debug rather than interrupting the progress
	// spinner.
	MsgFetchFailedFmt = "failed to fetch ip ranges for %s (run with --log-level DEBUG for details)"

	ErrUnmarshalFindResultFmt   = "error unmarshalling find result: %w"
	ErrUnmarshalRatingConfigFmt = "error unmarshalling rating config: %w"
)

const DefaultIndentSpaces = 2

const (
	RetryWaitMin    = 1 * time.Second
	RetryWaitMax    = 2 * time.Second
	RetryMax        = 1
	NameLookupDelay = 5 * time.Second
)

// Provider output priorities control the order results are rendered in, from
// the lowest number at the top of the output to the highest at the bottom.
// They are banded by how specifically a match identifies the host: a
// hand-annotated prefix or a blocklist hit names this exact address, a SaaS or
// crawler range names who operates it, and a hyperscaler range only says who
// owns a very large block. Per-IP reputation and scanning APIs apply to almost
// any address, so they sit below ownership identity and above PTR / geolocation
// metadata that make no ownership or threat claim at all.
const (
	// Curated locally: entries you or your own infrastructure define.
	DefaultAnnotatedOutputPriority = 10
	DefaultIPURLOutputPriority     = 12
	DefaultAzureWAFOutputPriority  = 15

	// This exact address is listed as malicious, widening to the network
	// blocks and unallocated space at the end of the band.
	DefaultBlocklistDEOutputPriority     = 20
	DefaultCINSScoreOutputPriority       = 20
	DefaultGreenSnowOutputPriority       = 20
	DefaultEmergingThreatsOutputPriority = 20
	DefaultDShieldOutputPriority         = 24
	DefaultSpamhausOutputPriority        = 26
	DefaultCymruOutputPriority           = 28
	// Feodo names a botnet command and control server and Tor an anonymising
	// exit, both statements about this exact address rather than who owns it.
	DefaultFeodoOutputPriority = 22
	DefaultTorOutputPriority   = 29

	// Privacy relays and proxy egress: narrow, purpose-built ranges.
	DefaultiCloudPROutputPriority = 50
	DefaultZscalerOutputPriority  = 52
	DefaultMullvadOutputPriority  = 54

	// Named bots and crawlers: small ranges that identify a single agent.
	DefaultGooglebotOutputPriority     = 60
	DefaultBingbotOutputPriority       = 60
	DefaultApplebotOutputPriority      = 60
	DefaultDuckDuckBotOutputPriority   = 60
	DefaultAmazonbotOutputPriority     = 60
	DefaultCCBotOutputPriority         = 60
	DefaultPerplexityBotOutputPriority = 62
	DefaultOpenAIOutputPriority        = 62
	DefaultAnthropicOutputPriority     = 62
	DefaultAhrefsOutputPriority        = 64
	DefaultGoogleSCOutputPriority      = 66
	DefaultGoogleUTFOutputPriority     = 68

	// Vulnerability scanners: narrow ranges that name the source of a scan.
	DefaultDetectifyOutputPriority = 70
	DefaultTenableOutputPriority   = 70

	// Monitoring and uptime probes.
	DefaultUptimeRobotOutputPriority = 80
	DefaultPingdomOutputPriority     = 80
	DefaultStatusCakeOutputPriority  = 80
	DefaultBetterStackOutputPriority = 80
	DefaultChecklyOutputPriority     = 80
	DefaultDatadogOutputPriority     = 82
	DefaultNewRelicOutputPriority    = 82
	DefaultGrafanaOutputPriority     = 80
	DefaultSentryOutputPriority      = 80
	DefaultSite24x7OutputPriority    = 80
	DefaultUpdownOutputPriority      = 80
	DefaultUptrendsOutputPriority    = 80

	// SaaS egress ranges.
	DefaultGitHubOutputPriority     = 90
	DefaultGitLabOutputPriority     = 90
	DefaultStripeOutputPriority     = 90
	DefaultAtlassianOutputPriority  = 90
	DefaultZoomOutputPriority       = 90
	DefaultM365OutputPriority       = 90
	DefaultOktaOutputPriority       = 90
	DefaultIntercomOutputPriority   = 90
	DefaultSalesforceOutputPriority = 90

	// CDN and edge networks: the host fronts someone else's origin.
	DefaultCloudflareOutputPriority = 140
	DefaultFastlyOutputPriority     = 140
	DefaultAkamaiOutputPriority     = 140
	DefaultGcoreOutputPriority      = 140
	DefaultBunnyOutputPriority      = 140
	DefaultCDN77OutputPriority      = 140
	DefaultCacheFlyOutputPriority   = 140
	DefaultImpervaOutputPriority    = 140

	// Hosting and VPS providers: the range says little beyond "rented".
	DefaultHetznerOutputPriority      = 160
	DefaultLinodeOutputPriority       = 160
	DefaultVultrOutputPriority        = 160
	DefaultScalewayOutputPriority     = 160
	DefaultContaboOutputPriority      = 160
	DefaultLeasewebOutputPriority     = 160
	DefaultM247OutputPriority         = 160
	DefaultRenderOutputPriority       = 160
	DefaultFlyioOutputPriority        = 160
	DefaultOVHOutputPriority          = 160
	DefaultDigitalOceanOutputPriority = 160

	// Hyperscaler clouds: the broadest ownership ranges. GCP leads the band
	// because it narrows a hit down to Google Cloud rather than to Google as
	// a whole, which is the least specific claim any provider makes.
	DefaultGCPOutputPriority      = 180
	DefaultAWSOutputPriority      = 182
	DefaultAzureOutputPriority    = 182
	DefaultOCIOutputPriority      = 182
	DefaultIBMCloudOutputPriority = 182
	DefaultTencentOutputPriority  = 182
	DefaultAlibabaOutputPriority  = 182
	DefaultHuaweiOutputPriority   = 182
	DefaultGoogleOutputPriority   = 186

	// Reputation and scanning intelligence: enrichment that applies to almost
	// any address, so it sits below a match that names who operates the host.
	DefaultAbuseIPDBOutputPriority  = 190
	DefaultCriminalIPOutputPriority = 192
	DefaultVirusTotalOutputPriority = 194
	DefaultIPQSOutputPriority       = 196
	DefaultShodanOutputPriority     = 198

	// Generic per-address metadata that makes no ownership or threat claim.
	DefaultIPAPIOutputPriority   = 200
	DefaultPtrOutputPriority     = 210
	DefaultIPToASNOutputPriority = 220
)
