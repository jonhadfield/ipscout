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
// hand-annotated prefix or a blocklist hit names this exact address, whereas a
// hyperscaler range only says who owns a very large block of addresses.
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

	// Reputation and scanning intelligence describing this exact address.
	DefaultAbuseIPDBOutputPriority  = 30
	DefaultCriminalIPOutputPriority = 32
	DefaultVirusTotalOutputPriority = 34
	DefaultIPQSOutputPriority       = 36
	DefaultShodanOutputPriority     = 38

	// Privacy relays and proxy egress: narrow, purpose-built ranges.
	DefaultiCloudPROutputPriority = 50
	DefaultZscalerOutputPriority  = 52

	// Named bots and crawlers: small ranges that identify a single agent.
	DefaultGooglebotOutputPriority     = 60
	DefaultBingbotOutputPriority       = 60
	DefaultApplebotOutputPriority      = 60
	DefaultDuckDuckBotOutputPriority   = 60
	DefaultPerplexityBotOutputPriority = 62
	DefaultOpenAIOutputPriority        = 62
	DefaultAnthropicOutputPriority     = 62
	DefaultAhrefsOutputPriority        = 64
	DefaultGoogleSCOutputPriority      = 66
	DefaultGoogleUTFOutputPriority     = 68

	// Monitoring and uptime probes.
	DefaultUptimeRobotOutputPriority = 80
	DefaultPingdomOutputPriority     = 80
	DefaultStatusCakeOutputPriority  = 80
	DefaultBetterStackOutputPriority = 80
	DefaultChecklyOutputPriority     = 80
	DefaultDatadogOutputPriority     = 82
	DefaultNewRelicOutputPriority    = 82

	// SaaS egress ranges.
	DefaultGitHubOutputPriority    = 90
	DefaultStripeOutputPriority    = 90
	DefaultAtlassianOutputPriority = 90
	DefaultZoomOutputPriority      = 90

	// CDN and edge networks: the host fronts someone else's origin.
	DefaultCloudflareOutputPriority = 140
	DefaultFastlyOutputPriority     = 140
	DefaultAkamaiOutputPriority     = 140
	DefaultGcoreOutputPriority      = 140
	DefaultBunnyOutputPriority      = 140
	DefaultCDN77OutputPriority      = 140
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
	DefaultGoogleOutputPriority   = 186

	// Generic per-address metadata that makes no ownership or threat claim.
	DefaultIPAPIOutputPriority   = 200
	DefaultPtrOutputPriority     = 210
	DefaultIPToASNOutputPriority = 220
)
