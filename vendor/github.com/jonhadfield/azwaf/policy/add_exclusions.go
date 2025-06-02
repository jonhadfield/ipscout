package policy

import (
	"fmt"
	"strings"

	"github.com/jonhadfield/azwaf/config"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
)

// AddManagedRuleExclusionInput defines the exclusion to add to a managed rule set
type AddManagedRuleExclusionInput struct {
	Session *session.Session
	// included for test injection only
	RuleSetDefinitions    []*armfrontdoor.ManagedRuleSetDefinition
	DryRun                bool
	AutoBackup            bool
	RuleSets              []*armfrontdoor.ManagedRuleSet
	PolicyResourceID      config.ResourceID
	RuleSetType           *string
	RuleSetVersion        *string
	RuleGroup             string
	RuleID                string
	ExclusionRuleVariable armfrontdoor.ManagedRuleExclusionMatchVariable
	ExclusionRuleOperator armfrontdoor.ManagedRuleExclusionSelectorMatchOperator
	ExclusionRuleSelector string
	Debug                 bool
	ShowDiff              bool
	AppVersion            string
	// helper attribute: used to assess scope of change
	Scope string
}

type AddManagedRuleExclusionCLIInput struct {
	BaseCLIInput
	ShowDiff              bool
	SubscriptionID        string
	PolicyID              string
	RID                   config.ResourceID
	RuleSet               string
	RuleGroup             string
	RuleID                string
	ExclusionRuleVariable string
	ExclusionRuleOperator string
	ExclusionRuleSelector string
}

func (input *AddManagedRuleExclusionCLIInput) ParseConfig() (amrei *AddManagedRuleExclusionInput, err error) {
	var rsType, rsVersion string

	if input.RuleSet != "" {
		rsType, rsVersion, err = splitRuleSetName(input.RuleSet)

		if err != nil {
			return
		}
	}

	exclusionVar, exclusionOp, err := NormaliseExclusionInput(input.ExclusionRuleVariable, input.ExclusionRuleOperator)
	if err != nil {
		return
	}

	amrei = &AddManagedRuleExclusionInput{
		// SubscriptionID:        input.SubscriptionID,
		DryRun:                input.DryRun,
		PolicyResourceID:      input.RID,
		RuleSetType:           &rsType,
		RuleSetVersion:        &rsVersion,
		RuleGroup:             input.RuleGroup,
		RuleID:                input.RuleID,
		ExclusionRuleVariable: exclusionVar,
		ExclusionRuleOperator: exclusionOp,
		ExclusionRuleSelector: input.ExclusionRuleSelector,
		ShowDiff:              input.ShowDiff,
		Debug:                 input.Debug,
		AppVersion:            input.AppVersion,
	}

	amrei.Scope, err = GetAddManagedRuleExclusionProcessScope(*amrei)
	if err != nil {
		return
	}
	// TODO: error (warn?) if major change

	return amrei, nil
}

type GetPolicyInput struct {
	Session *session.Session
	// CLIPolicyID    string
	PolicyID config.ResourceID
	// SubscriptionID string
}

type GetPolicyOutput struct {
	Policy *armfrontdoor.WebApplicationFirewallPolicy
	// ResourceID config.ResourceID
}

func (input *GetPolicyInput) GetPolicy() (output GetPolicyOutput, err error) {
	// check if Policy exists
	output.Policy, err = GetRawPolicy(input.Session,
		input.PolicyID.SubscriptionID,
		input.PolicyID.ResourceGroup,
		input.PolicyID.Name)
	if err != nil {
		return output, err
	}

	return
}

func AddManagedRuleExclusion(cliInput *AddManagedRuleExclusionCLIInput) (err error) {
	funcName := GetFunctionName()

	s := session.New()

	policyID, err := GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
		SubscriptionID: cliInput.SubscriptionID,
		RawPolicyID:    cliInput.PolicyID,
		ConfigPath:     cliInput.ConfigPath,
	})
	if err != nil {
		return err
	}

	amrei, err := cliInput.ParseConfig()
	if err != nil {
		return
	}

	s.AppVersion = cliInput.AppVersion

	getPolicyInput := GetPolicyInput{
		Session:  s,
		PolicyID: policyID,
	}

	getPolicyOutput, err := getPolicyInput.GetPolicy()
	if err != nil {
		return
	}

	// get copy of policy for later comparison
	original, err := CopyPolicy(*getPolicyOutput.Policy)
	if err != nil {
		return
	}

	logrus.Debugf("%s | store copy of policy %s for later comparison", funcName, *original.Name)

	amrei.RuleSets = getPolicyOutput.Policy.Properties.ManagedRules.ManagedRuleSets
	amrei.PolicyResourceID = policyID
	// Session only needed in case we need to retrieve managed ruleset definitions list for
	// adding rule that may not already have exclusions
	amrei.Session = s

	if err = addManagedRuleExclusion(amrei); err != nil {
		return
	}

	patch, err := GeneratePolicyPatch(&GeneratePolicyPatchInput{
		Original: original,
		New:      *getPolicyOutput.Policy,
	})
	if err != nil {
		return
	}

	if patch.TotalDifferences == 0 {
		logrus.Debug("nothing to do")

		return
	}

	if patch.CustomRuleChanges != 0 {
		logrus.Errorf("unexpected custom rules changes. aborting")

		return
	}

	return ProcessPolicyChanges(&ProcessPolicyChangesInput{
		Session:          s,
		PolicyName:       *getPolicyOutput.Policy.Name,
		SubscriptionID:   getPolicyInput.PolicyID.SubscriptionID,
		ResourceGroup:    getPolicyInput.PolicyID.ResourceGroup,
		PolicyPostChange: *getPolicyOutput.Policy,
		DryRun:           cliInput.DryRun,
		ShowDiff:         cliInput.ShowDiff,
		Backup:           cliInput.AutoBackup,
		Debug:            cliInput.Debug,
	})
}

func addManagedRuleExclusion(input *AddManagedRuleExclusionInput) error {
	funcName := GetFunctionName()

	var err error

	// walk through ruleset lists, checking if the exclusion already exists and, if not, add it
	for x := range input.RuleSets {
		// bots rulesets don't allow exclusions
		if strings.Contains(*input.RuleSets[x].RuleSetType, "Bot") {
			continue
		}

		logrus.Debugf("%s | walking ruleset %s_%s",
			funcName,
			dashIfEmptyString(input.RuleSets[x].RuleSetType),
			dashIfEmptyString(input.RuleSets[x].RuleSetVersion))

		err = addToManagedRuleSet(input, input.RuleSets[x])
		if err == nil {
			// no error means we're done
			// if the rule doesn't exist, we'd have an error
			// if the exclusion already exists, we'd have an error
			return nil
		}

		switch {
		case strings.Contains(err.Error(), errRuleNotFound) && x < len(input.RuleSets)-1:
			// scenario expected if we've only checked first of multiple rulesets
			continue
		case err.Error() == errExclusionAlreadyExists:
			// no need to decorate if it already exists
			return err
		default:
			return err
		}
	}

	return nil
}

func addToManagedRuleSet(input *AddManagedRuleExclusionInput, mrs *armfrontdoor.ManagedRuleSet) (err error) {
	funcName := GetFunctionName()
	// required when running tests without init
	checkDebug(input.Debug)
	logrus.Tracef("%s | scope: %s", funcName, input.Scope)

	switch {
	case input.Scope == "":
		return fmt.Errorf("%s - %s", funcName, errScopeUndefined)
	case input.Scope == ScopeRuleSet:
		if err = appendExclusion(appendExclusionInput{
			appendScope:           input.Scope,
			managedRuleExclusions: &mrs.Exclusions,
			matchVariable:         input.ExclusionRuleVariable,
			matchOperator:         input.ExclusionRuleOperator,
			matchSelector:         input.ExclusionRuleSelector,
		}); err != nil {
			return
		}
	case strings.EqualFold(input.Scope, ScopeRuleGroup):
		// TODO: turn into function
		var ruleGroupFound bool

		for _, mrgo := range mrs.RuleGroupOverrides {
			logrus.Tracef("%s | comparing %s with %s", funcName, *mrgo.RuleGroupName, input.RuleGroup)

			if strings.EqualFold(input.Scope, ScopeRuleGroup) && !strings.EqualFold(*mrgo.RuleGroupName, input.RuleGroup) {
				// if we're adding to a rulegroup and it doesn't match, then continue
				continue
			}

			logrus.Debugf("%s | RuleGroupOverride: %s", funcName, dashIfEmptyString(mrgo.RuleGroupName))

			ruleGroupFound = true

			if err = appendExclusion(appendExclusionInput{
				appendScope:           input.Scope,
				managedRuleExclusions: &mrgo.Exclusions,
				matchVariable:         input.ExclusionRuleVariable,
				matchOperator:         input.ExclusionRuleOperator,
				matchSelector:         input.ExclusionRuleSelector,
			}); err != nil {
				return
			}
		}

		if !ruleGroupFound {
			return fmt.Errorf("%s - %s %s", funcName, input.RuleGroup, errRuleGroupNotFound)
		}
	case strings.EqualFold(input.Scope, ScopeRule):
		if err = addManagedRuleGroupOverrideRuleExclusions(&addManagedRuleGroupOverrideRuleExclusionsInput{
			session:               input.Session,
			ruleID:                input.RuleID,
			ruleGroup:             input.RuleGroup,
			ruleSet:               mrs,
			ruleSetDefinitions:    input.RuleSetDefinitions,
			subscriptionID:        input.PolicyResourceID.SubscriptionID,
			exclusionRuleOperator: input.ExclusionRuleOperator,
			exclusionRuleVariable: input.ExclusionRuleVariable,
			exclusionRuleSelector: input.ExclusionRuleSelector,
		}); err != nil {
			return
		}

		return nil
	default:
		return fmt.Errorf("%s - scope provided: '%s' %s", funcName, input.Scope, errScopeInvalid)
	}

	return nil
}

type addManagedRuleGroupOverrideRuleExclusionsInput struct {
	session               *session.Session
	subscriptionID        string
	ruleID, ruleGroup     string
	ruleSet               *armfrontdoor.ManagedRuleSet
	exclusionRuleVariable armfrontdoor.ManagedRuleExclusionMatchVariable
	exclusionRuleOperator armfrontdoor.ManagedRuleExclusionSelectorMatchOperator
	exclusionRuleSelector string
	// used for test injection
	ruleSetDefinitions []*armfrontdoor.ManagedRuleSetDefinition
}

// addManagedRuleGroupOverrideRuleExclusions accepts a slice of rule overrides and then attempts to match the given rule
// to which it will add the specified exclusion.
// note: if the rule does not already exist, then retrieve the default definition and add that,
// modified with the given input
func addManagedRuleGroupOverrideRuleExclusions(input *addManagedRuleGroupOverrideRuleExclusionsInput) (err error) {
	funcName := GetFunctionName()
	// looping through the rules in a single Managed rule override
	// add to result if no match
	for _, groupOverride := range input.ruleSet.RuleGroupOverrides {
		// check if rule groupOverride was found if we're adding at scope rule groupOverride
		for _, managedRule := range groupOverride.Rules {
			managedRule := managedRule

			// if we have a match, then check if proposed exclusion already exists before adding
			if managedRule != nil && *managedRule.RuleID == input.ruleID {
				logrus.Debugf("%s | matched rule id %s", funcName, input.ruleID)

				return appendExclusion(appendExclusionInput{
					appendScope:           ScopeRuleGroup,
					managedRuleExclusions: &managedRule.Exclusions,
					matchVariable:         input.exclusionRuleVariable,
					matchOperator:         input.exclusionRuleOperator,
					matchSelector:         input.exclusionRuleSelector,
				})
			}
		}
	}

	// if no match, then check if rule exists in definitions
	var ruleDefinition *armfrontdoor.ManagedRuleDefinition

	var groupName string

	logrus.Debugf("%s | looking for rule %s in rule set definition %s_%s", funcName, input.ruleID, *input.ruleSet.RuleSetType, *input.ruleSet.RuleSetVersion)

	if ruleDefinition, groupName, err = getRuleDefinition(&getRuleDefinitionInput{
		session:            input.session,
		subscriptionID:     input.subscriptionID,
		ruleSetType:        input.ruleSet.RuleSetType,
		ruleSetVersion:     input.ruleSet.RuleSetVersion,
		ruleID:             input.ruleID,
		ruleSetDefinitions: input.ruleSetDefinitions,
	}); err != nil {
		return
	}

	if ruleDefinition == nil {
		return fmt.Errorf("%s - cannot find rule %s in rule set definition %s_%s", funcName, input.ruleID, *input.ruleSet.RuleSetType, *input.ruleSet.RuleSetVersion)
	}

	// loop through existing groups once more to add rule override in the correct place
	for _, groupOverride := range input.ruleSet.RuleGroupOverrides {
		if *groupOverride.RuleGroupName != groupName {
			continue
		}

		// definition exists, so add rule
		managedRuleOverride := armfrontdoor.ManagedRuleOverride{
			RuleID:       ruleDefinition.RuleID,
			Action:       ruleDefinition.DefaultAction,
			EnabledState: ruleDefinition.DefaultState,
		}

		err = appendExclusion(appendExclusionInput{
			appendScope:           ScopeRuleGroup,
			managedRuleExclusions: &managedRuleOverride.Exclusions,
			matchVariable:         input.exclusionRuleVariable,
			matchOperator:         input.exclusionRuleOperator,
			matchSelector:         input.exclusionRuleSelector,
		})
		if err != nil {
			return
		}

		// add rule to existing
		groupOverride.Rules = append(groupOverride.Rules, &managedRuleOverride)

		return nil
	}

	// add group if missing
	logrus.Debugf("rule group override not found in existing policy so adding with definition")

	input.ruleSet.RuleGroupOverrides = append(input.ruleSet.RuleGroupOverrides, &armfrontdoor.ManagedRuleGroupOverride{
		RuleGroupName: &groupName,
		Exclusions:    nil,
		Rules: []*armfrontdoor.ManagedRuleOverride{
			{
				RuleID:       ruleDefinition.RuleID,
				Action:       ruleDefinition.DefaultAction,
				EnabledState: ruleDefinition.DefaultState,
				Exclusions: []*armfrontdoor.ManagedRuleExclusion{
					{
						MatchVariable:         &input.exclusionRuleVariable,
						Selector:              &input.exclusionRuleSelector,
						SelectorMatchOperator: &input.exclusionRuleOperator,
					},
				},
			},
		},
	})

	return nil
}

type getRuleDefinitionInput struct {
	session            *session.Session
	ruleSetDefinitions []*armfrontdoor.ManagedRuleSetDefinition
	subscriptionID     string
	ruleSetType        *string
	ruleSetVersion     *string
	ruleID             string
}

func getRuleDefinition(in *getRuleDefinitionInput) (ruleDef *armfrontdoor.ManagedRuleDefinition, groupName string, err error) {
	funcName := GetFunctionName()

	if in.ruleSetType == nil || in.ruleSetVersion == nil {
		err = fmt.Errorf(
			"%s - rule set type and version are required to get a rule definition",
			GetFunctionName())

		return
	}

	if len(in.ruleSetDefinitions) == 0 {
		in.ruleSetDefinitions, err = getRuleSetDefinitions(in.session, in.subscriptionID)
		if err != nil {
			return
		}
	}

	var matchingDefinition getMatchingDefinitionsOutput

	var match bool

	for _, rsd := range in.ruleSetDefinitions {
		rsd := rsd

		// if rule set doesn't match then continue
		if *rsd.Properties.RuleSetType != *in.ruleSetType || *rsd.Properties.RuleSetVersion != *in.ruleSetVersion {
			logrus.Tracef("%s | %s_%s no match for %s_%s", funcName, *rsd.Properties.RuleSetType, *rsd.Properties.RuleSetVersion, *in.ruleSetType, *in.ruleSetVersion)

			continue
		}

		logrus.Tracef("%s | calling getDefinitionMatchingExistingRuleSet with rule set %s_%s and rule %s", funcName, *in.ruleSetType, *in.ruleSetVersion, in.ruleID)

		match, matchingDefinition, err = getDefinitionMatchingExistingRuleSet(&getDefinitionsMatchingExistingRuleSetInput{
			scope:          ScopeRule,
			mrsd:           rsd,
			ruleSetType:    *in.ruleSetType,
			ruleSetVersion: *in.ruleSetVersion,
			ruleID:         in.ruleID,
		})
		if err != nil {
			return
		}
	}

	// if it's not found in the definitions then fail
	if !match {
		err = fmt.Errorf("%s - rule %s not found in rule set %s_%s", GetFunctionName(), in.ruleID, *in.ruleSetType, *in.ruleSetVersion)

		return
	}

	return matchingDefinition.RuleDefinition, *matchingDefinition.RuleGroupDefinition.RuleGroupName, err
}

type appendExclusionInput struct {
	appendScope           string
	managedRuleExclusions *[]*armfrontdoor.ManagedRuleExclusion
	matchVariable         armfrontdoor.ManagedRuleExclusionMatchVariable
	matchOperator         armfrontdoor.ManagedRuleExclusionSelectorMatchOperator
	matchSelector         string
}

// appendExclusion updates a slice of exclusions in-place
func appendExclusion(input appendExclusionInput) error {
	funcName := GetFunctionName()

	var newExclusions []*armfrontdoor.ManagedRuleExclusion

	for _, exclusion := range *input.managedRuleExclusions {
		exclusion := exclusion
		newExclusions = append(newExclusions, exclusion)

		mre := matchManagedRuleGroupOverrideExclusion(matchManagedRuleGroupOverrideExclusionInput{
			existingManagedRuleExclusion: exclusion,
			variable:                     input.matchVariable,
			operator:                     input.matchOperator,
			selector:                     input.matchSelector,
		})

		if mre {
			scopeOutput := strings.ToLower(printScope(input.appendScope))
			return fmt.Errorf("%s - %s exclusion already exists", funcName, scopeOutput)
		}
	}

	// it doesn't exist, so add to list of exclusions
	logrus.Debugf("%s - exclusion not found so adding", funcName)

	ruleVar := input.matchVariable
	ruleOp := input.matchOperator

	newExclusions = append(newExclusions, &armfrontdoor.ManagedRuleExclusion{
		MatchVariable:         &ruleVar,
		Selector:              &input.matchSelector,
		SelectorMatchOperator: &ruleOp,
	})

	// set existing pointer value of exclusions to refer to slice of new exclusions
	*input.managedRuleExclusions = newExclusions

	return nil
}
