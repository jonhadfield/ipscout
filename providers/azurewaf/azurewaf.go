package azurewaf

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/fatih/color"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/jonhadfield/azwaf/config"
	azwafLogging "github.com/jonhadfield/azwaf/logging"
	"github.com/jonhadfield/ipscout/cache"

	"github.com/jedib0t/go-pretty/v6/table"
	azwafPolicy "github.com/jonhadfield/azwaf/policy"
	azwafSession "github.com/jonhadfield/azwaf/session"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName      = "azurewaf"
	DocTTL            = 1 * time.Hour
	IndentPipeHyphens = " |-----"
)

type Config struct {
	_ struct{}
	session.Session
	Host   netip.Addr
	APIKey string
}

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating azurewaf client")

	// azwaf logs to its own isolated slog logger (silent by default). Route it
	// through the session logger only at debug, because azwaf reports a failed
	// api call at ERROR, which a default run would print over the progress
	// spinner. The failure is not lost: loadProviderData turns it into a line
	// that prints after the results, alongside the other providers that failed.
	if c.Logger != nil {
		if strings.EqualFold(c.Config.Global.LogLevel, "debug") {
			azwafLogging.SetLogger(c.Logger)
		} else {
			azwafLogging.SetLogger(slog.New(slog.DiscardHandler))
		}
	}

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.AzureWAF.Enabled != nil && *c.Providers.AzureWAF.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.AzureWAF.OutputPriority
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
}

func (c *ProviderClient) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	return nil, nil
}

func (c *ProviderClient) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	return providers.RateResult{}, nil
}

func unmarshalProviderData(rBody []byte) ([]*armfrontdoor.WebApplicationFirewallPolicy, error) {
	var res []*armfrontdoor.WebApplicationFirewallPolicy

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling azurewaf provider doc: %w", err)
	}

	return res, nil
}

// tenantRegexp picks the tenant out of the `az login` line azure appends to an
// expired credential error, so the command we suggest names the same tenant.
var tenantRegexp = regexp.MustCompile(`--tenant "?([0-9a-fA-F-]{36})"?`)

// azureAuthHint reports whether err is azure refusing the cached credentials
// rather than anything to do with the policy being asked for, and returns the
// one line worth showing. Azure answers these with a paragraph carrying trace
// and correlation ids, timestamps and the full az invocation; the part a user
// acts on is that the login has expired and which tenant to renew it against.
func azureAuthHint(err error) string {
	msg := err.Error()

	switch {
	case strings.Contains(msg, "AADSTS50173"), // grant expired or revoked
		strings.Contains(msg, "AADSTS700082"), // refresh token expired
		strings.Contains(msg, "AADSTS50076"),  // mfa required
		strings.Contains(msg, "AzureCLICredential: ERROR"),
		strings.Contains(msg, "az login"):
	default:
		return ""
	}

	login := "az login"
	if m := tenantRegexp.FindStringSubmatch(msg); m != nil {
		login = fmt.Sprintf("az login --tenant %s", m[1])
	}

	return fmt.Sprintf("azure waf: your azure credentials have expired, so its policies were not read. "+
		"re-authenticate with: %s", login)
}

func (c *ProviderClient) loadProviderData() error {
	as, err := azwafSession.New()
	if err != nil {
		return fmt.Errorf("error creating azure waf session: %w", err)
	}

	policies, err := getPolicies(c.Session, as)
	if err != nil {
		// an expired login is the common case here and is worth saying plainly,
		// because the azure error that describes it is a paragraph long and the
		// generic fetch-failed line does not say what to do about it
		if hint := azureAuthHint(err); hint != "" {
			c.Messages.AddError(hint)

			return fmt.Errorf("azure waf credentials expired: %w", providers.ErrFailureReported)
		}

		return fmt.Errorf("error getting azure waf policies: %w", err)
	}

	for _, policy := range policies {
		c.Logger.Debug("policy", "id", *policy.ID, "name", *policy.Name)
	}

	data, err := json.Marshal(policies)
	if err != nil {
		return fmt.Errorf("error marshalling azure waf policies: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.AzureWAF.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.AzureWAF.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error caching azure waf policies: %w", err)
	}

	return nil
}

func getPolicies(sess session.Session, azWAFSess *azwafSession.Session) ([]*armfrontdoor.WebApplicationFirewallPolicy, error) {
	var rps []*armfrontdoor.WebApplicationFirewallPolicy

	for _, resourceID := range sess.Providers.AzureWAF.ResourceIDs {
		rid := config.ParseResourceID(resourceID)

		rp, err := azwafPolicy.GetRawPolicy(azWAFSess, rid.SubscriptionID, rid.ResourceGroup, rid.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting policy: %w", err)
		}

		rps = append(rps, rp)
	}

	return rps, nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising azure waf client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("error checking cache for azurewaf provider data: %w", err)
	}

	if ok {
		c.Logger.Debug("azurewaf provider data found in cache")

		return nil
	}

	// load data from source and store in cache
	err = c.loadProviderData()
	if err != nil {
		return err
	}

	return nil
}

func loadTestData(l *slog.Logger) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/azurewaf/testdata/azurewaf_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting azurewaf test data file path: %w", err)
	}

	tdf, err := loadResultsFile(l, resultsFile)
	if err != nil {
		return nil, err
	}

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

func (c *ProviderClient) loadProviderDataFromCache() ([]*armfrontdoor.WebApplicationFirewallPolicy, error) {
	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc []*armfrontdoor.WebApplicationFirewallPolicy

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached azurewaf provider doc: %w", err)
		}
	} else {
		return nil, fmt.Errorf("%w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	var out []byte

	var err error

	// load test results data
	if c.UseTestData {
		var loadErr error

		out, loadErr = loadTestData(c.Logger)
		if loadErr != nil {
			return nil, loadErr
		}

		c.Logger.Debug("azure waf match returned from test data", "host", c.Host.String())

		return out, nil
	}

	policies, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, err
	}

	matches, err := matchIPToPolicyCustomRules(c.Host, policies)
	if err != nil {
		return nil, err
	}

	if matches == nil {
		return nil, providers.ErrNoMatchFound
	}

	c.Logger.Debug("azurewaf match found", "host", c.Host.String())

	var raw []byte

	raw, err = json.Marshal(matches)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	return raw, nil
}

func matchIPToPolicyCustomRules(host netip.Addr, policies []*armfrontdoor.WebApplicationFirewallPolicy) (*HostSearchResult, error) {
	var hostSearchResult *HostSearchResult

	for _, policy := range policies {
		var hasMatches bool

		var policyMatch PolicyMatch

		policyMatch.RID = config.ParseResourceID(*policy.ID)

		for _, rule := range policy.Properties.CustomRules.Rules {
			var customRuleMatch CustomRuleMatch

			for _, mc := range rule.MatchConditions {
				if *mc.Operator != "IPMatch" {
					continue
				}

				if !slices.Contains([]string{"RemoteAddr", "SocketAddr"}, string(*mc.MatchVariable)) {
					continue
				}

				for _, rawPrefix := range mc.MatchValue {
					// if prefix check it contains host
					var prefix netip.Prefix

					var err error
					if strings.Contains(*rawPrefix, "/") {
						prefix, err = netip.ParsePrefix(*rawPrefix)
						if err != nil {
							return nil, fmt.Errorf("error parsing prefix: %w", err)
						}
					} else {
						var addr netip.Addr

						addr, err = netip.ParseAddr(*rawPrefix)
						if err != nil {
							return nil, fmt.Errorf("error parsing address: %w", err)
						}

						prefix, err = addr.Prefix(addr.BitLen())
						if err != nil {
							return nil, fmt.Errorf("error creating prefix: %w", err)
						}
					}

					if prefix.Contains(host) {
						hasMatches = true
						customRuleMatch.Negate = *mc.NegateCondition
						customRuleMatch.RuleType = string(*rule.RuleType)
						customRuleMatch.Action = string(*rule.Action)
						customRuleMatch.Priority = *rule.Priority
						customRuleMatch.RuleName = *rule.Name
						customRuleMatch.Prefixes = append(customRuleMatch.Prefixes, prefix)
					}
				}
			}

			if len(customRuleMatch.Prefixes) > 0 {
				policyMatch.RID = config.ParseResourceID(*policy.ID)
				policyMatch.CustomRuleMatches = append(policyMatch.CustomRuleMatches, customRuleMatch)
			}
		}

		if hasMatches {
			if hostSearchResult == nil {
				hostSearchResult = &HostSearchResult{}
			}

			hostSearchResult.PolicyMatches = append(hostSearchResult.PolicyMatches, policyMatch)
		}
	}

	return hostSearchResult, nil
}

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.CreateTableDuration, ProviderName)()

	rowEmphasisColor := providers.RowEmphasisColor(c.Session)

	var result HostSearchResult

	if err := json.Unmarshal(data, &result); err != nil {
		switch {
		case errors.Is(err, providers.ErrNoDataFound):
			return nil, fmt.Errorf("data not loaded: %w", err)
		case errors.Is(err, providers.ErrFailedToFetchData):
			return nil, fmt.Errorf("error fetching azurewaf data: %w", err)
		case errors.Is(err, providers.ErrNoMatchFound):
			// reset the error as no longer useful for table creation
			return nil, nil
		default:
			return nil, fmt.Errorf("error loading azurewaf api response: %w", err)
		}
	}

	tw := table.NewWriter()

	var rows []table.Row

	// pad column to ensure title row fills the table
	var lastPolicyMatchRID string
	for _, policyMatch := range result.PolicyMatches {
		if lastPolicyMatchRID != policyMatch.RID.Raw {
			tw.AppendRow(table.Row{providers.PadRight("Policy", providers.Column1MinWidth), fmt.Sprintf("%s %s", color.HiWhiteString("Subscription"), policyMatch.RID.SubscriptionID)})
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s %s", color.HiWhiteString("Resource Group"), policyMatch.RID.ResourceGroup)})
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s %s", color.HiWhiteString("Policy Name"), policyMatch.RID.Name)})
			lastPolicyMatchRID = policyMatch.RID.Raw
		}

		var lastCustomRuleMatchRuleName string
		for _, customRuleMatch := range policyMatch.CustomRuleMatches {
			if lastCustomRuleMatchRuleName != customRuleMatch.RuleName {
				tw.AppendRow(table.Row{"", rowEmphasisColor("Rule: %s", customRuleMatch.RuleName)})
				lastCustomRuleMatchRuleName = customRuleMatch.RuleName
			}

			for _, prefix := range customRuleMatch.Prefixes {
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s Prefix %s", IndentPipeHyphens, providers.DashIfEmpty(prefix.String()))})
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s Priority %s", IndentPipeHyphens, providers.DashIfEmpty(customRuleMatch.Priority))})
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s Action %s", IndentPipeHyphens, providers.DashIfEmpty(customRuleMatch.Action))})
				tw.AppendRow(table.Row{"", fmt.Sprintf("%s Negate %t", IndentPipeHyphens, customRuleMatch.Negate)})
			}
		}

		tw.AppendRows(rows)
		tw.SetColumnConfigs([]table.ColumnConfig{
			{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
		})
		tw.SetAutoIndex(false)
		tw.SetTitle("AZURE WAF | Host: %s", c.Host.String())

		if c.UseTestData {
			tw.SetTitle("AZURE WAF | Host: 165.232.46.239")
		}
	}

	return &tw, nil
}

func loadResultsFile(l *slog.Logger, path string) (*HostSearchResult, error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}

	defer func() {
		if err = jf.Close(); err != nil {
			l.Error("error closing file", "error", err.Error())
		}
	}()

	var res HostSearchResult

	decoder := json.NewDecoder(jf)

	if err = decoder.Decode(&res); err != nil {
		return nil, fmt.Errorf("error decoding json: %w", err)
	}

	return &res, nil
}

type PolicyMatch struct {
	RID               config.ResourceID
	CustomRuleMatches []CustomRuleMatch
}

type PrefixMatch struct {
	Prefix        string
	Negate        bool
	MatchVariable string
	Operator      string
}

type CustomRuleMatch struct {
	RuleName string
	RuleType string
	Prefixes []netip.Prefix
	Negate   bool
	Action   string
	Priority int32
}

type HostSearchResult struct {
	Raw           []byte
	PolicyMatches []PolicyMatch
	CreateDate    time.Time `json:"createDate"`
}
