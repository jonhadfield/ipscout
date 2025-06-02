package policy

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
)

type RuleSetStatsOutput struct {
	// rule set
	RuleSetType    string
	RuleSetVersion string

	// rules
	Rules                             int
	RulesEnabled                      int
	RulesDisabled                     int
	RulesDefaultEnabledStateOveridden int
	RulesDefaultActionOveridden       int
	BlockTotal                        int
	AllowTotal                        int
	LogTotal                          int
	RedirectTotal                     int
	GroupCount                        int

	// exclusions
	RuleSetScopeExclusionsTotal   int
	RuleGroupScopeExclusionsTotal int
	RuleScopeExclusionsTotal      int
	TotalExclusions               int
}

type BotRuleSetStatsOutput struct {
	// rule set
	RuleSetType    string
	RuleSetVersion string

	// rules
	Rules         int
	RulesEnabled  int
	RulesDisabled int
	BlockTotal    int
	AllowTotal    int
	LogTotal      int
	RedirectTotal int
	GroupCount    int

	// exclusions
	RuleSetScopeExclusionsTotal   int
	RuleGroupScopeExclusionsTotal int
	RuleScopeExclusionsTotal      int
	TotalExclusions               int
}

// getPolicyStats returns counts for all items in a rule set
func getPolicyStats(policy *armfrontdoor.WebApplicationFirewallPolicy, mrsd []*armfrontdoor.ManagedRuleSetDefinition) ([]RuleSetStatsOutput, error) {
	funcName := GetFunctionName()

	var stats []RuleSetStatsOutput

	if policy == nil || policy.Properties == nil || policy.Properties.ManagedRules == nil || len(policy.Properties.ManagedRules.ManagedRuleSets) == 0 {
		return stats, fmt.Errorf("%s - policy not defined", funcName)
	}

	if len(mrsd) == 0 || mrsd[0].Properties == nil {
		return stats, fmt.Errorf("%s - managed ruleset definitions not provided", funcName)
	}

	for _, rs := range policy.Properties.ManagedRules.ManagedRuleSets {
		rs := rs
		matchingDefinitionsOutput := getDefinitionMatchingExistingRuleSets(&getDefinitionsMatchingExistingRuleSetsInput{
			mrsdl:          mrsd,
			ruleSetType:    *rs.RuleSetType,
			ruleSetVersion: *rs.RuleSetVersion,
		})

		if matchingDefinitionsOutput.RuleSetDefinition == nil {
			return stats, fmt.Errorf(
				fmt.Sprintf("failed to get matching definition for rule set %s_%s",
					*rs.RuleSetType, *rs.RuleSetVersion), funcName)
		}

		stats = append(stats, getRuleSetStats(rs, matchingDefinitionsOutput.RuleSetDefinition))
	}

	return stats, nil
}
