package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jonhadfield/azwaf/config"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
)

// CopyRulesInput are the arguments provided to the CopyRules function.
type CopyRulesInput struct {
	BaseCLIInput
	SubscriptionID   string
	Source           string
	Target           string
	CustomRulesOnly  bool
	ManagedRulesOnly bool
	DryRun           bool
	ShowDiff         bool
	Debug            bool
	Async            bool
	Quiet            bool
	AppVersion       string
}

// CopyRules copies managed and custom rules between policies with matching rule sets
func CopyRules(i CopyRulesInput) error {
	funcName := GetFunctionName()
	if strings.EqualFold(i.Source, i.Target) {
		return fmt.Errorf("%s - source and target must be different", funcName)
	}

	s := session.New()

	SourceResourceID, err := GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
		SubscriptionID: i.SubscriptionID,
		RawPolicyID:    i.Source,
		ConfigPath:     i.ConfigPath,
	})
	if err != nil {
		return err
	}

	TargetResourceID, err := GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
		SubscriptionID: i.SubscriptionID,
		RawPolicyID:    i.Target,
		ConfigPath:     i.ConfigPath,
	})
	if err != nil {
		return err
	}

	logrus.Debug("copy source: ", i.Source)
	logrus.Debug("copy target: ", i.Target)

	sourcePolicy, err := GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
		SubscriptionID:    SourceResourceID.SubscriptionID,
		FilterResourceIDs: []string{SourceResourceID.Raw},
	})
	if err != nil {
		return fmt.Errorf(err.Error(), funcName)
	}

	if len(sourcePolicy.Policies) == 0 {
		return fmt.Errorf("%s - source policy not found", funcName)
	}

	targetPolicy, err := GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{
		SubscriptionID:    TargetResourceID.SubscriptionID,
		FilterResourceIDs: []string{TargetResourceID.Raw},
	})
	if err != nil {
		return err
	}

	// originalTargetPolicy, err := CopyPolicy(targetPolicy.Policies[0].Policy)
	// if err != nil {
	// 	return fmt.Errorf(err.Error(), funcName)
	// }

	if len(targetPolicy.Policies) == 0 {
		return fmt.Errorf("%s - target policy not found", funcName)
	}

	if !i.CustomRulesOnly && !HaveEqualRuleSets(&sourcePolicy.Policies[0].Policy, &targetPolicy.Policies[0].Policy) {
		return fmt.Errorf("%s - source and target policies must have matching managed rule set types and versions when copying managed rule settings", funcName)
	}

	logrus.Debugf("%s | policies have matching managed ruleset types and versions", funcName)

	// check change is required
	o, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{
		Original: sourcePolicy.Policies[0].Policy,
		New:      targetPolicy.Policies[0].Policy,
	})
	if err != nil {
		return fmt.Errorf(err.Error(), funcName)
	}

	logrus.Debugf("%s | custom rule changes %d managed rule changes %d total differences %d", funcName, o.CustomRuleChanges, o.ManagedRuleChanges, o.TotalDifferences)

	switch {
	case o.CustomRuleChanges == 0 && i.CustomRulesOnly:
		logrus.Warnf("%s | custom rules are already identical", funcName)

		return nil
	case o.ManagedRuleChanges == 0 && i.ManagedRulesOnly:
		logrus.Warnf("%s | managed rules are already identical", funcName)

		return nil
	case o.TotalRuleDifferences == 0:
		logrus.Warnf("%s | rules are already identical", funcName)

		return nil
	}

	updatedTarget, err := copyWrappedPolicyRules(&sourcePolicy.Policies[0], &targetPolicy.Policies[0], i.CustomRulesOnly, i.ManagedRulesOnly, i.AppVersion)
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	return ProcessPolicyChanges(&ProcessPolicyChangesInput{
		Session:          s,
		PolicyName:       updatedTarget.Name,
		SubscriptionID:   updatedTarget.SubscriptionID,
		ResourceGroup:    updatedTarget.ResourceGroup,
		PolicyPostChange: updatedTarget.Policy,
		ShowDiff:         i.ShowDiff,
		DryRun:           i.DryRun,
		Backup:           i.AutoBackup,
		Debug:            i.Debug,
	})
}

// copyWrappedPolicyRules takes two policies and copies the chosen sections from source to the target
func copyWrappedPolicyRules(source, target *WrappedPolicy, customRulesOnly, managedRulesOnly bool, appVersion string) (*WrappedPolicy, error) {
	funcName := GetFunctionName()

	updatedTarget, err := copyPolicyRules(&source.Policy, &target.Policy, customRulesOnly, managedRulesOnly)
	if err != nil {
		return nil, fmt.Errorf("%s - %w", funcName, err)
	}

	if updatedTarget.ID == nil {
		return nil, fmt.Errorf("%s - updated policy has no id", funcName)
	}

	resourceID := config.ParseResourceID(*updatedTarget.ID)

	return &WrappedPolicy{
		Date:           time.Now(),
		SubscriptionID: resourceID.SubscriptionID,
		ResourceGroup:  resourceID.ResourceGroup,
		Name:           resourceID.Name,
		Policy:         *updatedTarget,
		PolicyID:       *updatedTarget.ID,
		AppVersion:     appVersion,
	}, nil
}

// copyPolicyRules takes two policies and copies the chosen sections from source to the target
func copyPolicyRules(source, target *armfrontdoor.WebApplicationFirewallPolicy, customRulesOnly, managedRulesOnly bool) (*armfrontdoor.WebApplicationFirewallPolicy, error) {
	if customRulesOnly && managedRulesOnly {
		return nil, fmt.Errorf("please choose only one of custom-only and managed-only, or neither to copy both")
	}

	switch {
	case source == nil:
		return nil, fmt.Errorf("%s - source policy is missing", GetFunctionName())
	case customRulesOnly || !managedRulesOnly:
		if source.Properties.ManagedRules == nil {
			return nil, fmt.Errorf("source policy has no managed rules")
		}
	case target == nil:
		return nil, fmt.Errorf("%s - target policy is missing", GetFunctionName())
	}

	switch {
	case customRulesOnly:
		target.Properties.CustomRules = source.Properties.CustomRules
	case managedRulesOnly:
		fmt.Printf("copying managed rules to policy: %#+v\n", target.Properties)
		fmt.Printf("copying managed rules to: %#+v\n", target.Properties)
		fmt.Printf("copying managed rules to: %#+v\n", target.Properties.ManagedRules)
		fmt.Printf("copying managed rules from: %#+v \n", source.Properties.ManagedRules)
		target.Properties.ManagedRules = source.Properties.ManagedRules
	default:
		fmt.Printf("copying managed rules to policy: %#+v\n", target.Properties)
		target.Properties.CustomRules = source.Properties.CustomRules
		target.Properties.ManagedRules = source.Properties.ManagedRules
	}

	return target, nil
}

func (c *CopyRulesInput) Validate() error {
	funcName := GetFunctionName()

	if c.CustomRulesOnly && c.ManagedRulesOnly {
		return fmt.Errorf("%s - please choose only one of custom-only and managed-only, or neither to copy both", funcName)
	}

	if err := ValidateResourceID(c.Source, false); err != nil {
		return fmt.Errorf("%s - source id error: %w", funcName, err)
	}

	if err := ValidateResourceID(c.Target, false); err != nil {
		return fmt.Errorf("%s - target id error: %w", funcName, err)
	}

	if err := validateSubscriptionID(c.SubscriptionID); err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	return nil
}

// CopyPolicy takes an instance of a policy and returns a duplicate
func CopyPolicy(original armfrontdoor.WebApplicationFirewallPolicy) (armfrontdoor.WebApplicationFirewallPolicy, error) {
	funcName := GetFunctionName()

	originalBytes, err := json.Marshal(original)
	if err != nil {
		return armfrontdoor.WebApplicationFirewallPolicy{}, fmt.Errorf("%s - %w", funcName, err)
	}

	var duplicate armfrontdoor.WebApplicationFirewallPolicy
	if err = json.Unmarshal(originalBytes, &duplicate); err != nil {
		return armfrontdoor.WebApplicationFirewallPolicy{}, fmt.Errorf("%s - %w", funcName, err)
	}

	return duplicate, nil
}

// CopyWrappedPolicy takes an instance of a wrapped policy and returns a duplicate
func CopyWrappedPolicy(original *WrappedPolicy) (*WrappedPolicy, error) {
	funcName := GetFunctionName()

	var duplicate *WrappedPolicy

	originalBytes, err := json.Marshal(original)
	if err != nil {
		return duplicate, fmt.Errorf("%s - %w", funcName, err)
	}

	if err = json.Unmarshal(originalBytes, &duplicate); err != nil {
		return nil, fmt.Errorf("%s - %w", funcName, err)
	}

	return duplicate, nil
}
