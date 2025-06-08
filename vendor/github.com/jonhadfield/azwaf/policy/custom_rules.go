package policy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
	"go4.org/netipx"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

type filterCustomRulesInput struct {
	names       []string
	namePrefix  RuleNamePrefix
	customRules []*armfrontdoor.CustomRule
	action      *armfrontdoor.ActionType
	ruleType    *armfrontdoor.RuleType
}

func customRuleNamePrefixCheck(in filterCustomRulesInput, cr *armfrontdoor.CustomRule) bool {
	if in.namePrefix == "" {
		return false
	}

	if (in.action != nil && *in.action != *cr.Action) ||
		(in.ruleType != nil && *in.ruleType != *cr.RuleType) ||
		(in.namePrefix != "" && !strings.HasPrefix(*cr.Name, string(in.namePrefix))) {

		return false
	}

	return true
}

func customRuleNamesCheck(in filterCustomRulesInput, cr *armfrontdoor.CustomRule) bool {
	if len(in.names) == 0 || cr == nil {
		return false
	}

	for _, name := range in.names {
		if (in.action != nil && *in.action != *cr.Action) ||
			(in.ruleType != nil && *in.ruleType != *cr.RuleType) ||
			(*cr.Name != name) {

			continue
		}

		return true
	}

	return false
}

func filterCustomRules(in filterCustomRulesInput) ([]*armfrontdoor.CustomRule, error) {
	if in.customRules == nil {
		return nil, fmt.Errorf("filtering custom rules requires a list of custom rules")
	}

	if in.ruleType == nil {
		return nil, errors.New("filtering custom rules requires a type is set")
	}

	if in.action == nil {
		return nil, errors.New("filtering custom rules requires an action is set")
	}

	var filtered []*armfrontdoor.CustomRule

	for _, cr := range in.customRules {
		cr := cr

		if customRuleNamesCheck(in, cr) {
			filtered = append(filtered, cr)

			// only one name can match
			return filtered, nil
		}

		if customRuleNamePrefixCheck(in, cr) {
			filtered = append(filtered, cr)
		}
	}

	return filtered, nil
}

func getIPNetsForPrefix(customRules []*armfrontdoor.CustomRule, action *armfrontdoor.ActionType) ([]netip.Prefix, []netip.Prefix, error) {
	var positive, negative []netip.Prefix

	if action == nil {
		return nil, nil, errors.New("action cannot be nil")
	}

	for _, cr := range customRules {
		cr := cr

		mc := cr.MatchConditions

		// for each match conditions, get the
		for y := range mc {
			// ensure match condition is IP as rules with mixed match
			// conditions (IPMatch + GeoMatch combination)
			// are not currently supported
			if !matchConditionSupported(mc[y]) {
				return nil, nil, fmt.Errorf("rule %s has match condition that does not match constraints", *cr.Name)
			}

			for z := range mc[y].MatchValue {
				n, tErr := tryNetStrToPrefix(*mc[y].MatchValue[z])
				if tErr != nil {
					return nil, nil, tErr
				}

				if *mc[y].NegateCondition {
					negative = append(negative, n)
				} else {
					positive = append(positive, n)
				}
			}
		}
	}

	return positive, negative, nil
}

func getIPNetsForRuleIPMatchConditions(cr *armfrontdoor.CustomRule) ([]netip.Prefix, []netip.Prefix, error) {
	var positive, negative []netip.Prefix

	mc := cr.MatchConditions

	// for each match conditions, get the
	for y := range mc {
		// ensure match condition is IP as rules with mixed match
		// conditions (IPMatch + GeoMatch combination)
		//  are not currently supported
		if !matchConditionSupported(mc[y]) {
			continue
			// return nil, nil, fmt.Errorf("rule %s has match condition that does not match constraints", *cr.Name)
		}

		for z := range mc[y].MatchValue {
			n, tErr := tryNetStrToPrefix(*mc[y].MatchValue[z])
			if tErr != nil {
				return nil, nil, tErr
			}

			if *mc[y].NegateCondition {
				negative = append(negative, n)
			} else {
				positive = append(positive, n)
			}
		}
	}

	return positive, negative, nil
}

func getNonIPMatchConditions(cr *armfrontdoor.CustomRule) []*armfrontdoor.MatchCondition {
	var result []*armfrontdoor.MatchCondition

	mc := cr.MatchConditions

	// for each match conditions, get the
	for y := range mc {
		// ensure match condition is IP as rules with mixed match
		// conditions (IPMatch + GeoMatch combination)
		//  are not currently supported
		if *mc[y].Operator == armfrontdoor.OperatorIPMatch {
			continue
		}

		result = append(result, mc[y])
	}

	return result
}

type RemoveNetsInput struct {
	BaseCLIInput
	Session       *session.Session
	RawResourceID string
	MatchPrefix   RuleNamePrefix
	RuleType      *armfrontdoor.RuleType
	ResourceID    config.ResourceID
	Action        *armfrontdoor.ActionType
	Filepath      string
	Nets          []netip.Prefix
	MaxRules      int
	// can be called from external so allow override
	LogLevel *logrus.Level
}

type ApplyRemoveNetsInput struct {
	BaseCLIInput
	RID         config.ResourceID
	MatchPrefix RuleNamePrefix
	Action      *armfrontdoor.ActionType
	RuleType    *armfrontdoor.RuleType
	Output      bool
	DryRun      bool
	Filepath    string
	Addrs       IPNets
	MaxRules    int
	// can be called from external so allow override
	LogLevel *logrus.Level
}

// RemoveNets removes selected networks from custom rules
func RemoveNets(input *RemoveNetsInput) ([]ApplyRemoveNetsResult, error) {
	if input.LogLevel != nil {
		logrus.SetLevel(*input.LogLevel)
	}

	if input.RuleType == nil {
		return nil, errors.New("rule type cannot be nil")
	}

	if input.Session == nil {
		input.Session = session.New()
	}

	policyID := input.ResourceID

	var err error

	if policyID.Raw == "" {
		if IsRIDHash(input.RawResourceID) {
			policyID, err = GetPolicyResourceIDByHash(input.Session, input.SubscriptionID, input.RawResourceID)

			if err != nil {
				return nil, err
			}
		}
	}

	results, err := ApplyRemoveAddrs(input.Session, &ApplyRemoveNetsInput{
		BaseCLIInput: input.BaseCLIInput,
		MatchPrefix:  input.MatchPrefix,
		RID:          policyID,
		Output:       input.Quiet,
		DryRun:       input.DryRun,
		Filepath:     input.Filepath,
		RuleType:     input.RuleType,
		Action:       input.Action,
		Addrs:        input.Nets,
		MaxRules:     0,
		LogLevel:     input.LogLevel,
	})

	return results, err
}

// getNetsToRemove adds the IPs from the specified file to the list of IPs to remove
func getNetsToRemove(path string, inNets IPNets) (IPNets, error) {
	var err error

	var outNets IPNets

	if path != "" {
		var fipns IPNets

		fipns, err = loadIPsFromPath(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load IPs from path: %s", err)
		}

		outNets = fipns
	}

	outNets = append(outNets, inNets...)

	if len(outNets) == 0 {
		return nil, errors.New("no ips to unblock provided")
	}

	return outNets, nil
}

type ApplyRemoveNetsResult struct {
	Addr     netip.Prefix
	PolicyID string
	Removed  bool
}
type ApplyRemoveNetsResults []ApplyRemoveNetsResult

// getLowestPriority returns the lowest priority assigned to a rule starting with the specified prefix
func getLowestPriority(rules []*armfrontdoor.CustomRule, prefix RuleNamePrefix) int32 {
	var hadPrefixMatch bool

	var lowest int32

	for x := range rules {
		// if the custom rule is not a block rule, then add (remove all existing block rules)
		if strings.HasPrefix(*rules[x].Name, string(prefix)) {
			// if it's zero then we have our lowest
			if *rules[x].Priority == 0 {
				break
			}

			// if it's the first one, then set this as the start priority
			if !hadPrefixMatch {
				hadPrefixMatch = true

				lowest = *rules[x].Priority
			}

			// set lowest if priority is lower
			if *rules[x].Priority < lowest {
				lowest = *rules[x].Priority
			}
		}
	}

	return lowest
}

// ApplyRemoveAddrs removes selected networks from custom rules
func ApplyRemoveAddrs(s *session.Session, input *ApplyRemoveNetsInput) ([]ApplyRemoveNetsResult, error) {
	var results []ApplyRemoveNetsResult

	lowercaseAction := strings.ToLower(actionBlock)

	inNets, err := getNetsToRemove(input.Filepath, input.Addrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get networks to remove: %s", err)
	}

	p, originalPolicy, existingPositiveNets, _, err := loadPolicyNets(s, input.RID, input.MatchPrefix, input.Action)
	if err != nil {
		return nil, err
	}

	trimmed, results := buildTrimmedNetworks(inNets, existingPositiveNets, input.RID.Raw)

	if err = replaceRulesAndPush(s, p, originalPolicy, trimmed, input, lowercaseAction); err != nil {
		return nil, err
	}

	return results, nil
}

func loadPolicyNets(s *session.Session, rid config.ResourceID, prefix RuleNamePrefix, action *armfrontdoor.ActionType) (*armfrontdoor.WebApplicationFirewallPolicy, armfrontdoor.WebApplicationFirewallPolicy, []netip.Prefix, []netip.Prefix, error) {
	p, err := GetRawPolicy(s, rid.SubscriptionID, rid.ResourceGroup, rid.Name)
	if err != nil {
		return nil, armfrontdoor.WebApplicationFirewallPolicy{}, nil, nil, fmt.Errorf("failed to get policy: %w", err)
	}
	if p.Name == nil {
		return nil, armfrontdoor.WebApplicationFirewallPolicy{}, nil, nil, fmt.Errorf("specified policy not found")
	}
	original, err := CopyPolicy(*p)
	if err != nil {
		return nil, armfrontdoor.WebApplicationFirewallPolicy{}, nil, nil, fmt.Errorf("failed to copy policy: %w", err)
	}
	filtered, err := filterCustomRules(filterCustomRulesInput{
		namePrefix:  prefix,
		customRules: p.Properties.CustomRules.Rules,
	})
	if err != nil {
		return nil, armfrontdoor.WebApplicationFirewallPolicy{}, nil, nil, err
	}
	pos, neg, err := getIPNetsForPrefix(filtered, action)
	if err != nil {
		return nil, armfrontdoor.WebApplicationFirewallPolicy{}, nil, nil, err
	}
	logrus.Tracef("existing %s positive nets: %d negative nets: %d", prefix, len(pos), len(neg))
	return p, original, pos, neg, nil
}

func buildTrimmedNetworks(inNets, existing []netip.Prefix, policyID string) ([]netip.Prefix, []ApplyRemoveNetsResult) {
	var trimmed []netip.Prefix
	var results []ApplyRemoveNetsResult
	for _, inNet := range inNets {
		if slices.Contains(existing, inNet) {
			results = append(results, ApplyRemoveNetsResult{Addr: inNet, PolicyID: policyID, Removed: true})
		} else {
			results = append(results, ApplyRemoveNetsResult{Addr: inNet, PolicyID: policyID, Removed: false})
		}
	}
	for _, n := range existing {
		if !slices.Contains(inNets, n) {
			trimmed = append(trimmed, n)
		}
	}
	return trimmed, results
}

func replaceRulesAndPush(s *session.Session, p *armfrontdoor.WebApplicationFirewallPolicy, original armfrontdoor.WebApplicationFirewallPolicy, trimmed []netip.Prefix, input *ApplyRemoveNetsInput, action string) error {
	proposedRules, err := GenCustomRulesFromIPNets(GenCustomRulesFromIPNetsInput{
		PositiveMatchNets:   trimmed,
		RuleType:            input.RuleType,
		Action:              input.Action,
		MaxRules:            input.MaxRules,
		CustomNamePrefix:    input.MatchPrefix,
		CustomPriorityStart: int(getLowestPriority(p.Properties.CustomRules.Rules, input.MatchPrefix)),
	})
	if err != nil {
		return fmt.Errorf("failed to generate custom rules: %w", err)
	}
	var ecrs []*armfrontdoor.CustomRule
	for _, existingCustomRule := range p.Properties.CustomRules.Rules {
		if !strings.HasPrefix(*existingCustomRule.Name, string(input.MatchPrefix)) {
			ecrs = append(ecrs, existingCustomRule)
		}
	}
	ecrs = append(ecrs, proposedRules...)
	sort.Slice(ecrs, func(i, j int) bool { return *ecrs[i].Priority < *ecrs[j].Priority })
	p.Properties.CustomRules.Rules = ecrs
	if len(p.Properties.CustomRules.Rules) > MaxCustomRules {
		return fmt.Errorf("operation exceededs custom rules limit of %d", MaxCustomRules)
	}
	gppO, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{Original: original, New: *p})
	if err != nil {
		return fmt.Errorf("failed to generate policy patch: %w", err)
	}
	if gppO.CustomRuleChanges == 0 {
		logrus.Debug("nothing to do")
		return nil
	}
	if input.DryRun {
		logrus.Infof("%s | %d changes to %s list would be applied\n", GetFunctionName(), gppO.CustomRuleChanges, action)
		return nil
	}
	np, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}
	diffsFound, err := compare(&original, np)
	if err != nil {
		return fmt.Errorf("failed to compare policies: %w", err)
	}
	logrus.Debugf("diffsFound: %t", diffsFound)
	logrus.Printf("updating policy %s", *p.Name)
	return PushPolicy(s, &PushPolicyInput{
		Name:          *p.Name,
		Subscription:  input.RID.SubscriptionID,
		ResourceGroup: input.RID.ResourceGroup,
		Policy:        *p,
	})
}

type DecorateExistingCustomRuleInput struct {
	BaseCLIInput
	Policy                  *armfrontdoor.WebApplicationFirewallPolicy
	SubscriptionID          string
	RawResourceID           string
	ResourceID              config.ResourceID
	Action                  *armfrontdoor.ActionType
	Output                  bool
	Filepath                string
	AdditionalAddrs         IPNets
	AdditionalExcludedAddrs IPNets
	RuleName                string
	RuleType                *armfrontdoor.RuleType
	// RateLimitDurationInMinutes *int32
	// RateLimitThreshold         *int32
	PriorityStart int
	// StartRuleNumber int
	MaxRules int
	// can be called from external so allow override
	LogLevel *logrus.Level
}

type UpdatePolicyCustomRulesIPMatchPrefixesInput struct {
	BaseCLIInput
	Policy                     *armfrontdoor.WebApplicationFirewallPolicy
	SubscriptionID             string
	RawResourceID              string
	ResourceID                 config.ResourceID
	Action                     *armfrontdoor.ActionType
	Output                     bool
	Filepath                   string
	Addrs                      IPNets
	ReplaceAddrs               bool
	ExcludedAddrs              IPNets
	RuleNamePrefix             RuleNamePrefix
	RuleType                   *armfrontdoor.RuleType
	RateLimitDurationInMinutes *int32
	RateLimitThreshold         *int32
	PriorityStart              int
	// StartRuleNumber int
	MaxRules int
	// can be called from external so allow override
	LogLevel *logrus.Level
}

func loadLocalPrefixes(filepath string, prefixes IPNets) (IPNets, error) {
	var res IPNets

	var err error

	if filepath != "" {
		res, err = loadIPsFromPath(filepath)
		if err != nil {
			return nil, fmt.Errorf("failed to load IPs from path: %s", err)
		}
	}

	res = append(res, prefixes...)

	if len(res) == 0 {
		return prefixes, errors.New("no local prefixes loaded")
	}

	return res, nil
}

// getGroupByFromRules returns the GroupBy clause from the first rule if one
// exists.  It returns an empty slice if there are no rules.
func getGroupByFromRules(rules []*armfrontdoor.CustomRule) []*armfrontdoor.GroupByVariable {
	if len(rules) == 0 {
		return []*armfrontdoor.GroupByVariable{}
	}

	return rules[0].GroupBy
}

// mergePrefixesWithExisting appends the IP prefixes extracted from existing
// rules to the provided positive and negative prefix slices.  The resulting
// slices are normalised before being returned.
func mergePrefixesWithExisting(rules []*armfrontdoor.CustomRule, action *armfrontdoor.ActionType, pos, neg IPNets) (IPNets, IPNets, error) {
	existingPos, existingNeg, err := getIPNetsForPrefix(rules, action)
	if err != nil {
		return nil, nil, err
	}

	pos = append(pos, existingPos...)
	pos, err = Normalise(pos)
	if err != nil {
		return nil, nil, err
	}

	neg = append(neg, existingNeg...)
	neg, err = Normalise(neg)
	if err != nil {
		return nil, nil, err
	}

	return pos, neg, nil
}

// replaceRulesWithPrefix removes any existing custom rules whose name has the
// supplied prefix and appends the provided rules.
func replaceRulesWithPrefix(p *armfrontdoor.WebApplicationFirewallPolicy, prefix RuleNamePrefix, newRules []*armfrontdoor.CustomRule) {
	var cleaned []*armfrontdoor.CustomRule

	for _, r := range p.Properties.CustomRules.Rules {
		if !strings.HasPrefix(*r.Name, string(prefix)) {
			cleaned = append(cleaned, r)
		}
	}

	p.Properties.CustomRules.Rules = append(cleaned, newRules...)
}

type RuleNamePrefix string

var (
	ruleNamePrefixTestStartNumber = regexp.MustCompile(`^[0-9].*`)
	ruleNamePrefixTestEndNumber   = regexp.MustCompile(`^[a-zA-Z]+[0-9]+$`)
)

func (r RuleNamePrefix) Check() error {
	rs := string(r)

	switch {
	case len(rs) == 0:
		return errors.New("rule name prefix cannot be empty")
	case ruleNamePrefixTestStartNumber.MatchString(rs):
		return errors.New("rule name prefix cannot start with a number")
	case ruleNamePrefixTestEndNumber.MatchString(rs):
		return errors.New("rule name prefix cannot end with a number")
	case strings.Contains(rs, " "):
		return errors.New("rule name prefix cannot contain white space")
	default:
		return nil
	}
}

func ValidateUpdatePolicyInput(in UpdatePolicyCustomRulesIPMatchPrefixesInput) error {
	funcName := GetFunctionName()

	if len(in.Addrs) == 0 && len(in.ExcludedAddrs) == 0 {
		return fmt.Errorf("no networks provided")
	}

	if in.Policy == nil {
		return fmt.Errorf("%s - policy is nil", funcName)
	}

	if in.Action == nil {
		return fmt.Errorf("%s - action is nil", funcName)
	}

	if slices.Contains(armfrontdoor.PossibleActionTypeValues(), *in.Action) {
		if err := in.RuleNamePrefix.Check(); err != nil {
			return err
		}
	}

	if in.Policy == nil {
		return fmt.Errorf("missing policy")
	}

	if in.Policy.Properties == nil {
		return fmt.Errorf("policy missing properties")
	}

	return nil
}

// UpdatePolicyCustomRulesIPMatchPrefixes updates an existing Custom Policy with prefixes matching the requested action
func UpdatePolicyCustomRulesIPMatchPrefixes(in UpdatePolicyCustomRulesIPMatchPrefixesInput) (bool, GeneratePolicyPatchOutput, error) {
	if err := ValidateUpdatePolicyInput(in); err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	if in.LogLevel != nil {
		logrus.SetLevel(*in.LogLevel)
	}

	// take a copy of the Policy for later comparison
	originalPolicy, err := CopyPolicy(*in.Policy)
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	positivePrefixes, err := loadLocalPrefixes(in.Filepath, in.Addrs)
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	negativePrefixes := in.ExcludedAddrs

	filtered, err := filterCustomRules(filterCustomRulesInput{
		namePrefix:  in.RuleNamePrefix,
		customRules: in.Policy.Properties.CustomRules.Rules,
		action:      in.Action,
		ruleType:    in.RuleType,
	})
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	// get groupby clause from filtered to ensure we generate new custom rules with the same
	gbv := getGroupByFromRules(filtered)

	// if we're not replacing the existing rules, then append the existing rules to the new rules
	if !in.ReplaceAddrs {
		positivePrefixes, negativePrefixes, err = mergePrefixesWithExisting(filtered, in.Action, positivePrefixes, negativePrefixes)
		if err != nil {
			return false, GeneratePolicyPatchOutput{}, err
		}
	}

	crs, err := GenCustomRulesFromIPNets(GenCustomRulesFromIPNetsInput{
		PositiveMatchNets:          positivePrefixes,
		NegativeMatchNets:          negativePrefixes,
		GroupBy:                    gbv,
		RuleType:                   in.RuleType,
		RateLimitDurationInMinutes: in.RateLimitDurationInMinutes,
		RateLimitThreshold:         in.RateLimitThreshold,
		Action:                     in.Action,
		MaxRules:                   in.MaxRules,
		CustomNamePrefix:           in.RuleNamePrefix,
		CustomPriorityStart:        in.PriorityStart,
	})
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	// remove existing rules with the prefix and append the new ones
	replaceRulesWithPrefix(in.Policy, in.RuleNamePrefix, crs)
	// o, _ := json.MarshalIndent(in.Policy.Properties.CustomRules.Rules, "", "  ")

	if len(in.Policy.Properties.CustomRules.Rules) > MaxCustomRules {
		return false, GeneratePolicyPatchOutput{}, fmt.Errorf("operation exceededs custom rules limit of %d", MaxCustomRules)
	}

	// sort rules by priority
	sortRulesByPriority(in.Policy.Properties.CustomRules.Rules)
	sortRulesByPriority(originalPolicy.Properties.CustomRules.Rules)

	patch, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{Original: originalPolicy, New: *in.Policy})
	if err != nil {
		return false, patch, err
	}

	if patch.TotalDifferences == 0 {
		logrus.Debug("nothing to do")

		return false, patch, nil
	}

	if patch.ManagedRuleChanges != 0 {
		return true, patch, fmt.Errorf("unexpected Managed rules changes. aborting")
	}

	return true, patch, nil
}

func sortRulesByPriority(rules []*armfrontdoor.CustomRule) {
	sort.Slice(rules, func(i, j int) bool {
		return *rules[i].Priority < *rules[j].Priority
	})
}

func getRateLimitConfig(rules []*armfrontdoor.CustomRule) (*int32, *int32, error) {
	var lastDuration *int32

	var lastThreshold *int32

	// ensure all rules have the same rate limit configuration
	for x, cr := range rules {
		cr := cr

		ruleName := "not defined"
		if cr.Name != nil {
			ruleName = *cr.Name
		}

		if cr.RuleType == nil {
			return nil, nil, fmt.Errorf("rule %d - %s has no rule type", x, ruleName)
		}

		switch *cr.RuleType {
		case armfrontdoor.RuleTypeRateLimitRule:
			if cr.RateLimitDurationInMinutes == nil {
				return nil, nil, fmt.Errorf("rate limit rule %s has no rate limit duration", ruleName)
			}

			if cr.RateLimitThreshold == nil {
				return nil, nil, fmt.Errorf("rate limit rule %s has no rate limit threshold", ruleName)
			}
		case armfrontdoor.RuleTypeMatchRule:
			if cr.RateLimitDurationInMinutes != nil || cr.RateLimitThreshold != nil {
				return nil, nil, fmt.Errorf("match rule %s has rate limit configuration", ruleName)
			}
		default:
			return nil, nil, fmt.Errorf("rule %s has unknown rule type", ruleName)
		}

		// grab the first rule's rate limit configuration
		if x == 0 {
			// if the first rule has a rate limit configuration, then set the lastDuration and lastThreshold
			if cr.RateLimitDurationInMinutes != nil && cr.RateLimitThreshold != nil {
				lastDuration = cr.RateLimitDurationInMinutes
				lastThreshold = cr.RateLimitThreshold

				continue
			}
		}

		// check each rule has the same non-existant/existant rate limit configuration
		if cr.RateLimitDurationInMinutes != nil && cr.RateLimitThreshold != nil {
			if (lastThreshold != nil && *lastThreshold != *cr.RateLimitThreshold) || (lastDuration != nil && *lastDuration != *cr.RateLimitDurationInMinutes) {
				return nil, nil, fmt.Errorf("rules have different rate limit configurations")
			}
		}
	}

	return lastThreshold, lastDuration, nil
}

func ValidateDecorateExistingCustomRuleInput(in DecorateExistingCustomRuleInput) error {
	funcName := GetFunctionName()

	if len(in.AdditionalAddrs) == 0 && len(in.AdditionalExcludedAddrs) == 0 {
		return fmt.Errorf("no networks provided")
	}

	if in.Policy == nil {
		return fmt.Errorf("%s - policy is nil", funcName)
	}

	if in.Policy.Properties.CustomRules == nil {
		return fmt.Errorf("%s - policy has no custom rules section", funcName)
	}

	if in.Policy.Properties.CustomRules.Rules == nil {
		return fmt.Errorf("%s - policy has no custom rules", funcName)
	}

	if in.Policy.Properties == nil {
		return fmt.Errorf("policy missing properties")
	}

	if in.RuleName == "" {
		return fmt.Errorf("rule name cannot be empty")
	}

	if in.RuleType == nil {
		return fmt.Errorf("rule type cannot be nil")
	}

	return nil
}

// rebuild the IP match conditions for the "IP Address" match type
func rebuildIPMatchConditions(ruleToDecorate *armfrontdoor.CustomRule, additionalPositivePrefixes, additionalNegativePrefixes []netip.Prefix) ([]*armfrontdoor.MatchCondition, []*armfrontdoor.MatchCondition, error) {
	var posMatchConditions, negMatchConditions []*armfrontdoor.MatchCondition

	existingPositiveAddrs, existingNegativeAddrs, err := getIPNetsForRuleIPMatchConditions(ruleToDecorate)
	if err != nil {
		return posMatchConditions, negMatchConditions, err
	}

	// get a copy of the existing ipnets for the specified action and append to the list of new nets
	additionalPositivePrefixes = append(additionalPositivePrefixes, existingPositiveAddrs...)

	// appending existingAddrs to new set may result in overlap so normalise
	additionalPositivePrefixes, err = Normalise(additionalPositivePrefixes)
	if err != nil {
		return posMatchConditions, negMatchConditions, err
	}

	additionalNegativePrefixes = append(additionalNegativePrefixes, existingNegativeAddrs...)
	// appending existingAddrs to new set may result in overlap so normalise
	additionalNegativePrefixes, err = Normalise(additionalNegativePrefixes)
	if err != nil {
		return posMatchConditions, negMatchConditions, err
	}

	// get number of those to negate that must appear in each rule
	// this will be deducted from max values per rule
	deDupedNegatedNets := deDupeIPNets(additionalNegativePrefixes)
	sort.Strings(deDupedNegatedNets)
	logrus.Tracef("total negated networks after deduplication: %d", len(deDupedNegatedNets))

	deDupedNets := deDupeIPNets(additionalPositivePrefixes)
	sort.Strings(deDupedNets)

	positiveMatchConditions, err := generateMatchConditionsFromNets(generateMatchConditionsFromNetsInput{
		nets:                  &deDupedNets,
		negate:                false,
		maxValuesPerCondition: MaxIPMatchValues - len(deDupedNegatedNets),
		// TODO: should respect the existing match variable
		matchVariable: toPtr(armfrontdoor.MatchVariableSocketAddr),
		matchOperator: toPtr(armfrontdoor.OperatorIPMatch),
	})
	if err != nil {
		return posMatchConditions, negMatchConditions, err
	}

	logrus.Tracef("positive match conditions: %d", len(positiveMatchConditions))

	// generate the match conditions to add to each rule
	negativeMatchConditions, err := generateMatchConditionsFromNets(generateMatchConditionsFromNetsInput{
		nets:   &deDupedNegatedNets,
		negate: true,
		// TODO: set to Max (600) minus the largest possible chunk of positive
		maxValuesPerCondition: MaxIPMatchValues,
		matchVariable:         toPtr(armfrontdoor.MatchVariableSocketAddr),
		matchOperator:         toPtr(armfrontdoor.OperatorIPMatch),
	})
	if err != nil {
		return posMatchConditions, negMatchConditions, err
	}

	logrus.Tracef("negative match conditions: %d", len(negativeMatchConditions))

	return positiveMatchConditions, negativeMatchConditions, nil
}

// DecorateExistingCustomRule adds to an existing Custom Policy with prefixes matching the requested action
func DecorateExistingCustomRule(in DecorateExistingCustomRuleInput) (bool, GeneratePolicyPatchOutput, error) {
	if err := ValidateDecorateExistingCustomRuleInput(in); err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	if in.LogLevel != nil {
		logrus.SetLevel(*in.LogLevel)
	}

	// take a copy of the Policy for later comparison
	originalPolicy, err := CopyPolicy(*in.Policy)
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	// positivePrefixes are those to match without negation
	var positivePrefixes []netip.Prefix
	if in.Filepath != "" || len(in.AdditionalAddrs) > 0 {
		positivePrefixes, err = loadLocalPrefixes(in.Filepath, in.AdditionalAddrs)
		if err != nil {
			return false, GeneratePolicyPatchOutput{}, err
		}
	}

	// retrieve specified rule by name
	filtered, err := filterCustomRules(filterCustomRulesInput{
		names:       []string{in.RuleName},
		customRules: in.Policy.Properties.CustomRules.Rules,
		ruleType:    in.RuleType,
		action:      in.Action,
	})
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	if len(filtered) == 0 {
		if in.Policy.Name != nil {
			return false, GeneratePolicyPatchOutput{}, fmt.Errorf("no custom rule found with name %s, type %s, action %s in policy %s", in.RuleName, *in.RuleType, *in.Action, *in.Policy.Name)
		}

		return false, GeneratePolicyPatchOutput{}, fmt.Errorf("no custom rule found with name %s, type %s, and action %s", in.RuleName, *in.RuleType, *in.Action)
	}

	ruleToDecorate := filtered[0]

	// start creating a replacement list of match conditions by starting
	// with the existing non-IP match conditions
	replacementMatchConditions := getNonIPMatchConditions(ruleToDecorate)

	positiveMatchConditions, negativeMatchConditions, err := rebuildIPMatchConditions(ruleToDecorate, positivePrefixes, in.AdditionalExcludedAddrs)
	if err != nil {
		return false, GeneratePolicyPatchOutput{}, err
	}

	replacementMatchConditions = append(replacementMatchConditions, positiveMatchConditions...)
	replacementMatchConditions = append(replacementMatchConditions, negativeMatchConditions...)

	// replace match conditions
	ruleToDecorate.MatchConditions = replacementMatchConditions

	sortCustomRulesByPriority(in.Policy.Properties.CustomRules.Rules)
	sortCustomRulesByPriority(originalPolicy.Properties.CustomRules.Rules)

	patch, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{Original: originalPolicy, New: *in.Policy})
	if err != nil {
		return false, patch, err
	}

	// op, _ := json.MarshalIndent(originalPolicy, "", "  ")
	// os.WriteFile("orig", op, 0644)

	// np, _ := json.MarshalIndent(*in.Policy, "", "  ")
	// os.WriteFile("new", np, 0644)

	if patch.TotalDifferences == 0 {
		logrus.Debug("nothing to do")

		return false, patch, nil
	}

	if patch.ManagedRuleChanges != 0 {
		return true, patch, fmt.Errorf("unexpected Managed rules changes. aborting")
	}

	return true, patch, nil
}

func sortCustomRulesByPriority(in []*armfrontdoor.CustomRule) {
	sort.Slice(in, func(i, j int) bool {
		return *in[i].Priority < *in[j].Priority
	})
}

type IPNets []netip.Prefix

// toString receives slice of net.IPNet and returns a slice of their string representations
func (i *IPNets) toString() []string {
	var res []string

	for x := range *i {
		ipn := (*i)[x]
		res = append(res, ipn.String())
	}

	return res
}

// deDupeIPNets accepts a slice of net.IPNet and returns a unique slice of their string representations
func deDupeIPNets(ipns IPNets) []string {
	var res []string

	// check overlaps
	seen := make(map[string]bool)

	for _, i := range ipns.toString() {
		if _, ok := seen[i]; ok {
			continue
		}

		res = append(res, i)
		seen[i] = true
	}

	return res
}

// Normalise accepts a slice of netip.Prefix and returns a unique slice of their string representations
func Normalise(iPrefixes []netip.Prefix) ([]netip.Prefix, error) {
	ipsetBuilder := netipx.IPSetBuilder{}

	for x := range iPrefixes {
		if !iPrefixes[x].IsValid() {
			logrus.Errorf("invalid prefix: %s\n", iPrefixes[x].String())

			continue
		}

		ipsetBuilder.AddPrefix(iPrefixes[x])
	}

	ipSet, err := ipsetBuilder.IPSet()
	if err != nil {
		return nil, err
	}

	logrus.Tracef("normalised %d to %d prefixes", len(iPrefixes), len(ipSet.Prefixes()))

	return ipSet.Prefixes(), nil
}

type GenCustomRulesFromIPNetsInput struct {
	PositiveMatchNets          IPNets
	NegativeMatchNets          IPNets
	GroupBy                    []*armfrontdoor.GroupByVariable
	RuleType                   *armfrontdoor.RuleType
	RateLimitDurationInMinutes *int32
	RateLimitThreshold         *int32
	Action                     *armfrontdoor.ActionType
	MaxRules                   int
	CustomNamePrefix           RuleNamePrefix
	CustomPriorityStart        int
}

// validateGenCustomRulesInput ensures required fields are set and valid
func validateGenCustomRulesInput(in GenCustomRulesFromIPNetsInput) error {
	if in.Action == nil {
		return fmt.Errorf("action cannot be nil")
	}

	if !slices.Contains(armfrontdoor.PossibleActionTypeValues(), *in.Action) {
		return fmt.Errorf("invalid action: %s", *in.Action)
	}

	if in.RuleType == nil {
		return fmt.Errorf("rule type cannot be nil")
	}

	if !slices.Contains(armfrontdoor.PossibleRuleTypeValues(), *in.RuleType) {
		return fmt.Errorf("invalid rule type: %s %w", *in.RuleType, ErrInvalidRuleType)
	}

	return nil
}

// prepareMatchConditions converts provided prefixes into match conditions for rule generation
func prepareMatchConditions(in GenCustomRulesFromIPNetsInput) ([]*armfrontdoor.MatchCondition, []*armfrontdoor.MatchCondition, error) {
	deDupedNegatedNets := deDupeIPNets(in.NegativeMatchNets)
	sort.Strings(deDupedNegatedNets)
	logrus.Tracef("total negated networks after deduplication: %d", len(deDupedNegatedNets))

	deDupedNets := deDupeIPNets(in.PositiveMatchNets)
	sort.Strings(deDupedNets)
	logrus.Tracef("total networks after deduplication: %d", len(deDupedNets))

	if len(deDupedNegatedNets) >= 599 {
		return nil, nil, fmt.Errorf("%d negated match values specified but cannot exceed 599", len(deDupedNegatedNets))
	}

	positiveMatchConditions, err := generateMatchConditionsFromNets(generateMatchConditionsFromNetsInput{
		nets:                  &deDupedNets,
		negate:                false,
		maxValuesPerCondition: MaxIPMatchValues - len(deDupedNegatedNets),
		matchVariable:         toPtr(armfrontdoor.MatchVariableSocketAddr),
		matchOperator:         toPtr(armfrontdoor.OperatorIPMatch),
	})
	if err != nil {
		return nil, nil, err
	}

	logrus.Tracef("positive match conditions: %d", len(positiveMatchConditions))

	negativeMatchConditions, err := generateMatchConditionsFromNets(generateMatchConditionsFromNetsInput{
		nets:                  &deDupedNegatedNets,
		negate:                true,
		maxValuesPerCondition: MaxIPMatchValues,
		matchVariable:         toPtr(armfrontdoor.MatchVariableSocketAddr),
		matchOperator:         toPtr(armfrontdoor.OperatorIPMatch),
	})
	if err != nil {
		return nil, nil, err
	}

	logrus.Tracef("negative match conditions: %d", len(negativeMatchConditions))

	return positiveMatchConditions, negativeMatchConditions, nil
}

// buildCustomRules iterates over match conditions and creates the resulting custom rules
func buildCustomRules(pos, neg []*armfrontdoor.MatchCondition, in GenCustomRulesFromIPNetsInput, start int32) []*armfrontdoor.CustomRule {
	var crs []*armfrontdoor.CustomRule

	priorityCount := start

	for x := range pos {
		mcs := []*armfrontdoor.MatchCondition{pos[x]}
		if len(neg) == 1 {
			mcs = append(mcs, neg[0])
		}

		cr := genCustomRuleFromMatchConditions(genCustomRuleFromMatchConditionsInput{
			mcs:                        mcs,
			priority:                   priorityCount,
			action:                     in.Action,
			groupBy:                    in.GroupBy,
			namePrefix:                 string(in.CustomNamePrefix),
			ruleType:                   in.RuleType,
			rateLimitDurationInMinutes: in.RateLimitDurationInMinutes,
			rateLimitThreshold:         in.RateLimitThreshold,
		})

		logrus.Tracef("generated match condition: %d", priorityCount+1)

		crs = append(crs, &cr)

		priorityCount++

		if len(crs) == in.MaxRules {
			break
		}
	}

	return crs
}

// GenCustomRulesFromIPNets accepts two lists of IPs (positive and negative), plus the action to be taken with them, and the maximum
// number of rules to create and then returns a slice of CustomRules
func GenCustomRulesFromIPNets(in GenCustomRulesFromIPNetsInput) ([]*armfrontdoor.CustomRule, error) {
	if err := validateGenCustomRulesInput(in); err != nil {
		return nil, err
	}

	priorityStart := int32(in.CustomPriorityStart)

	pos, neg, err := prepareMatchConditions(in)
	if err != nil {
		return nil, err
	}

	crs := buildCustomRules(pos, neg, in, priorityStart)

	sort.Slice(crs, func(i, j int) bool {
		return *crs[i].Priority < *crs[j].Priority
	})

	return crs, nil
}

type genCustomRuleFromMatchConditionsInput struct {
	mcs                        []*armfrontdoor.MatchCondition
	priority                   int32
	action                     *armfrontdoor.ActionType
	groupBy                    []*armfrontdoor.GroupByVariable
	enabled                    *armfrontdoor.CustomRuleEnabledState
	namePrefix                 string
	ruleType                   *armfrontdoor.RuleType
	rateLimitDurationInMinutes *int32
	rateLimitThreshold         *int32
}

func genCustomRuleFromMatchConditions(in genCustomRuleFromMatchConditionsInput) armfrontdoor.CustomRule {
	name := fmt.Sprintf("%s%d", in.namePrefix, in.priority)

	return armfrontdoor.CustomRule{
		Action:                     in.action,
		MatchConditions:            in.mcs,
		Priority:                   &in.priority,
		RuleType:                   in.ruleType,
		GroupBy:                    in.groupBy,
		EnabledState:               toPtr(armfrontdoor.CustomRuleEnabledStateEnabled),
		Name:                       &name,
		RateLimitDurationInMinutes: in.rateLimitDurationInMinutes,
		RateLimitThreshold:         in.rateLimitThreshold,
	}
}

type generateMatchConditionsFromNetsInput struct {
	nets                  *[]string
	negate                bool
	maxValuesPerCondition int
	matchVariable         *armfrontdoor.MatchVariable
	matchOperator         *armfrontdoor.Operator
}

func generateMatchConditionsFromNets(in generateMatchConditionsFromNetsInput) (mcs []*armfrontdoor.MatchCondition, err error) {
	var chunk []*string

	for x, net := range *in.nets {
		net := net
		chunk = append(chunk, &net)

		// if we've reached the end, or max chunk size then add match
		// condition and reset chunk
		if x+1 == len(*in.nets) || len(chunk) == in.maxValuesPerCondition {
			var mc armfrontdoor.MatchCondition

			sort.Slice(chunk, func(i, j int) bool {
				return netipx.ComparePrefix(netip.MustParsePrefix(*chunk[i]), netip.MustParsePrefix(*chunk[j])) < 0
			})

			mc.MatchValue = chunk
			mc.NegateCondition = toPtr(in.negate)
			mc.Operator = in.matchOperator
			mc.MatchVariable = toPtr(armfrontdoor.MatchVariableSocketAddr)
			mc.Transforms = []*armfrontdoor.TransformType{}

			mcs = append(mcs, &mc)

			// reset chunk
			chunk = []*string{}
		}
	}

	return
}

// readIPsFromFile accepts a file path from which to load IPs (one per line) as strings and return a slice of
func readIPsFromFile(fPath string) (IPNets, error) {
	var ipnets IPNets

	// #nosec
	file, err := os.Open(fPath)
	if err != nil {
		log.Fatalf("failed to open")
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	var ipnet netip.Prefix

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			if !strings.Contains(line, "/") {
				line += "/32"
			}

			ipnet, err = netip.ParsePrefix(line)
			if err != nil {
				return nil, fmt.Errorf("failed to parse prefix: %s", err)
			}

			ipnets = append(ipnets, ipnet)
		}
	}

	return ipnets, nil
}

// loadIPsFromPath accepts a file path or directory and then generates a fully qualified path
// in order to call a function to load the ips from each fully qualified file path
func loadIPsFromPath(path string) (IPNets, error) {
	var ipNets IPNets

	// if path is a folder, then loop through contents
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("path %s does not exist", path)
	}

	if info.IsDir() {
		var files []os.DirEntry

		files, err = os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory: %s", err)
		}

		if len(files) == 0 {
			return nil, fmt.Errorf("no files found in %s", path)
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}

			var n IPNets

			p := filepath.Join(path, file.Name())

			n, err = readIPsFromFile(p)
			if err != nil {
				return nil, fmt.Errorf("failed to load ips from file: %s", err)
			}

			logrus.Infof("loaded %d ips from file %s", len(n), p)

			ipNets = append(ipNets, n...)
		}

		return ipNets, nil
	}

	var n IPNets

	n, err = readIPsFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load ips from file: %s", err)
	}

	logrus.Debugf("loaded %d ips from file %s", len(n), path)

	ipNets = append(ipNets, n...)

	return ipNets, nil
}

type AddCustomRulesPrefixesInput struct {
	BaseCLIInput
	Session        *session.Session
	Policy         *armfrontdoor.WebApplicationFirewallPolicy
	SubscriptionID string
	RawResourceID  string
	ResourceID     config.ResourceID
	Action         armfrontdoor.ActionType
	Output         bool
	DryRun         bool
	Filepath       string
	Addrs          IPNets
	RuleNamePrefix RuleNamePrefix
	PriorityStart  int
	// StartRuleNumber int
	MaxRules int
	// can be called from external so allow override
	LogLevel *logrus.Level
}

// matchConditionSupported returns true if is for IPMatch
// and is for remote address or socket addresses
func matchConditionSupported(mc *armfrontdoor.MatchCondition) bool {
	if mc.MatchVariable == nil || mc.Operator == nil {
		logrus.Warnf("match condition missing variable or operator")

		return false
	}

	// removing a prefix is only valid for remote or socket address
	if !slices.Contains([]armfrontdoor.MatchVariable{armfrontdoor.MatchVariableRemoteAddr, armfrontdoor.MatchVariableSocketAddr}, *mc.MatchVariable) {
		logrus.Warnf("match condition is not remote address nor socket address so not valid for unblock")
		return false
	}

	if *mc.Operator != armfrontdoor.OperatorIPMatch {
		logrus.Warnf("match condition operator not ip match so not valid for unblock")
		return false
	}

	return true
}

func tryNetStrToPrefix(inNetStr string) (netip.Prefix, error) {
	// if no mask then try parsing as address
	if !strings.Contains(inNetStr, "/") {
		addr, err := netip.ParseAddr(inNetStr)
		if err != nil {
			return netip.Prefix{}, err
		}

		return addr.Prefix(addr.BitLen())
	}

	return netip.ParsePrefix(inNetStr)
}
