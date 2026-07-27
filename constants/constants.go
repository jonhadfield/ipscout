package constants

import "time"

const (
	AppName   = "ipscout"
	AppNameSC = "IPScout"

	ProviderNotDefinedFmt = "%s provider not defined in config"

	MsgInvalidHostFmt = "invalid host: %s"

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

const DefaultDigitalOceanOutputPriority = 200

const DefaultGCPOutputPriority = 200

const DefaultGoogleOutputPriority = 200

const DefaultGooglebotOutputPriority = 190

const DefaultGoogleSCOutputPriority = 190

const DefaultHetznerOutputPriority = 70

const DefaultOpenAIOutputPriority = 190

const DefaultiCloudPROutputPriority = 100

const DefaultIPAPIOutputPriority = 90

const DefaultIPToASNOutputPriority = 90

const DefaultIPQSOutputPriority = 50

const DefaultIPURLOutputPriority = 20

const DefaultLinodeOutputPriority = 140

const DefaultM247OutputPriority = 140

const DefaultOVHOutputPriority = 40

const DefaultPtrOutputPriority = 120

const DefaultShodanOutputPriority = 70

const DefaultVirusTotalOutputPriority = 40

const DefaultZscalerOutputPriority = 40

const (
	DefaultAbuseIPDBOutputPriority  = 50
	DefaultAnnotatedOutputPriority  = 30
	DefaultAtlassianOutputPriority  = 60
	DefaultAWSOutputPriority        = 200
	DefaultAzureOutputPriority      = 200
	DefaultAzureWAFOutputPriority   = 20
	DefaultBingbotOutputPriority    = 180
	DefaultBunnyOutputPriority      = 140
	DefaultCDN77OutputPriority      = 140
	DefaultContaboOutputPriority    = 140
	DefaultCriminalIPOutputPriority = 60
	DefaultDatadogOutputPriority    = 60
	DefaultFlyioOutputPriority      = 140
	DefaultIBMCloudOutputPriority   = 200
	DefaultImpervaOutputPriority    = 20
	DefaultLeasewebOutputPriority   = 140
	DefaultRenderOutputPriority     = 140
	DefaultStripeOutputPriority     = 60
	DefaultTencentOutputPriority    = 200
)
