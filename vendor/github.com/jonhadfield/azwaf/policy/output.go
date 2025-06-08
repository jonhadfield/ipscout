package policy

import (
	"encoding/json"
	errors2 "errors"
	"fmt"
	"hash/adler32"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/jonhadfield/azwaf/config"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/alexeyco/simpletable"
	"github.com/gookit/color"

	"github.com/jonhadfield/azwaf/session"
	"github.com/jonhadfield/findexec"
	"github.com/sirupsen/logrus"
)

const (
	maxColumnWidth        = 80
	shortURLLength        = 27
	lineLengthLimit       = 60
	geoCodeMaxLen         = 4
	valsPerGeoLine        = 4
	diffErrorExitCode     = 2
	trimDescriptionLength = 80
)

// splitExtendedID accepts an extended id <resource id>|<resource item name>, which it parses and then returns
// the individual components, or any error encountered in deriving them.
func splitExtendedID(eid string) (string, string, error) {
	components := strings.Split(eid, "|")
	if len(components) != 2 {
		return "", "", fmt.Errorf("invalid format")
	}

	return components[0], components[1], nil
}

// GetRawPolicyCustomRuleByID returns a Custom rule matching the resource id.
// The id is an extended resource id: <Policy>|<Custom rule name>.
func GetRawPolicyCustomRuleByID(s *session.Session, policyID config.ResourceID, customRuleName string) (armfrontdoor.CustomRule, error) {
	logrus.Debugf("getting policy with id %s", policyID.Name)

	p, err := GetRawPolicy(s, policyID.SubscriptionID, policyID.ResourceGroup, policyID.Name)
	if err != nil {
		return armfrontdoor.CustomRule{}, fmt.Errorf("failed to get policy: %s", err)
	}

	var pcr armfrontdoor.CustomRule

	for _, r := range p.Properties.CustomRules.Rules {
		if *r.Name == customRuleName {
			pcr = *r

			break
		}
	}

	if pcr.Name == nil {
		return pcr, fmt.Errorf("custom rule '%s' not found", customRuleName)
	}

	return pcr, nil
}

// PrintPolicyCustomRule outputs the Custom rule for a given resource.
// The id is an extended resource id: <Policy>|<Custom rule name>.
func PrintPolicyCustomRule(subscriptionID, extendedID, config string) error {
	s := session.New()

	policyID, customRuleName, err := splitExtendedID(extendedID)
	if err != nil {
		return fmt.Errorf("id not in the format <policy-id>|<custom-rule-name>")
	}

	resourceID, err := GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
		SubscriptionID: subscriptionID,
		RawPolicyID:    policyID,
		ConfigPath:     config,
	})
	if err != nil {
		return err
	}

	cr, err := GetRawPolicyCustomRuleByID(s, resourceID, customRuleName)
	if err != nil {
		return err
	}

	var b []byte

	b, err = json.MarshalIndent(cr, "", "    ")
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("failed to marshall Custom rule: %s", err.Error()), GetFunctionName())
	}

	fmt.Println(string(b))

	return nil
}

// PrintPolicy outputs the raw json Policy with the provided resource id.
func PrintPolicy(policyID, subscriptionID, configPath string) error {
	s := session.New()

	rid, err := GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
		SubscriptionID: subscriptionID,
		RawPolicyID:    policyID,
		ConfigPath:     configPath,
	})
	if err != nil {
		return err
	}

	p, err := GetRawPolicy(s, rid.SubscriptionID, rid.ResourceGroup, rid.Name)
	if err != nil {
		return err
	}

	b, jerr := json.MarshalIndent(p, "", "    ")
	if jerr != nil {
		return fmt.Errorf(
			fmt.Sprintf("failed to marshall Custom rule: %s", jerr.Error()), GetFunctionName())
	}

	fmt.Println(string(b))

	return nil
}

func computeAdler32(r string) string {
	// change to lower case to avoid inconsistent api responses
	r = strings.ToLower(r)

	h := adler32.New()
	// Write for hash.Hash never returns an error.
	_, _ = h.Write([]byte(r))

	hi := h.Sum32()

	return fmt.Sprintf("%x", hi)
}

// showFrontDoors displays a table listing front doors, their endpoints, and their associated Policies.
func showFrontDoors(afds FrontDoors) {
	table := simpletable.New()
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Front Door")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Endpoint")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Policy")},
		},
	}

	for _, afd := range afds {
		var r []*simpletable.Cell

		for x1, endpoint := range afd.endpoints {
			afdName := ""
			if x1 == 0 {
				afdName = afd.name
			}

			r = []*simpletable.Cell{
				{Text: afdName},
				{Text: endpoint.name},
				{Text: *endpoint.wafPolicy.Name},
			}
			table.Body.Cells = append(table.Body.Cells, r)
		}
	}

	table.Println()
}

// formatRuleEnabledState accepts a waf Policy's action type and returns a colored text representation
func formatRuleEnabledState(enabledState, defaultState string) string {
	if enabledState == "Enabled" {
		return color.Green.Sprint("Enabled")
	}

	if enabledState == "Disabled" {
		return color.Red.Sprint("Disabled")
	}

	// prevent infinite loop
	if defaultState != "Enabled" && defaultState != "Disabled" {
		panic(fmt.Sprintf("default state invalid: %s", defaultState))
	}

	return formatRuleEnabledState(defaultState, "")
}

// formatRuleAction accepts a waf Policy's action type and returns a colored text representation
func formatRuleAction(ruleAction interface{}) string {
	if ruleAction == nil {
		logrus.Debugf("rule action is nil\n")
		return ""
	}

	var action string

	switch val := ruleAction.(type) {
	case *armfrontdoor.ActionType:
		if val != nil && *val != "" {
			action = string(*val)
		}
	case *armfrontdoor.ManagedRuleSetActionType:
		if val != nil {
			action = string(*val)
		}
	default:
		logrus.Errorf("unexpected action type '%s'", reflect.TypeOf(ruleAction))
	}

	switch strings.ToLower(action) {
	case "block":
		return color.Red.Sprint("Block")
	case "anomalyscoring":
		return color.Red.Sprint("Anomaly Scoring")
	case "log":
		return color.Yellow.Sprint("Log")
	case "allow":
		return color.Green.Sprint("Allow")
	case "redirect":
		return color.Blue.Sprint("Redirect")

	case "":
		return ""
	default:
		logrus.Errorf("unexpected rule action '%s'", action)
	}

	return ""
}

func colourEnabledState(es string) string {
	if es == "Enabled" {
		return color.Green.Sprint(es)
	}

	if es == "Disabled" {
		return color.Red.Sprint(es)
	}

	logrus.Errorf("unexpected enabled state '%s'", es)

	return es
}

func outputCustomRules(policy *armfrontdoor.WebApplicationFirewallPolicy, showFull bool) {
	if ok, _ := HasCustomRules(policy); !ok {
		color.Bold.Println("Custom Rules:  None defined")

		return
	}

	table := simpletable.New()
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Rule Name")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("State")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Priority")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Rule Type")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Rate Limit Duration (mins)")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Rate Limit Threshold")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Action")},
		},
	}

	customRules := policy.Properties.CustomRules.Rules
	if len(customRules) > 0 {
		color.HiWhite.Println("Custom Rules")

		var maxCRNameLen int

		for _, cr := range customRules {
			// determine maximum characters for Custom rule name
			if len(*cr.Name) > maxCRNameLen {
				maxCRNameLen = len(*cr.Name)
			}

			rldim := " "
			if cr.RateLimitDurationInMinutes != nil && string(*cr.RuleType) == "RateLimitRule" {
				rldim = strconv.Itoa(int(*cr.RateLimitDurationInMinutes))
			}

			rlt := " "

			if cr.RateLimitThreshold != nil && string(*cr.RuleType) == "RateLimitRule" {
				rlt = strconv.Itoa(int(*cr.RateLimitThreshold))
			}

			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: color.BgDarkGray.Sprint(*cr.Name) + "\n" + strings.Repeat("-", 11)},
				{Text: colourEnabledState(string(*cr.EnabledState)) + "\n" + strings.Repeat("-", 9)},
				{Text: strconv.Itoa(int(*cr.Priority)) + "\n" + strings.Repeat("-", 10)},
				{Text: string(*cr.RuleType) + "\n" + strings.Repeat("-", 13)},
				{Text: rldim + "\n" + strings.Repeat("-", 28)},
				{Text: rlt + "\n" + strings.Repeat("-", 22)},
				{Align: simpletable.AlignCenter, Text: formatRuleAction(cr.Action) + "\n" + strings.Repeat("-", 8)},
			}, []*simpletable.Cell{
				{Text: color.HiBlue.Sprintf("Match Variable")},
				{Text: color.HiBlue.Sprintf("Selector")},
				{Text: color.HiBlue.Sprintf("Negate")},
				{Text: color.HiBlue.Sprintf("Operator")},
				{Text: color.HiBlue.Sprintf("Transforms")},
				{Text: color.HiBlue.Sprintf("Match Value")},
				{Text: ""},
			})

			for _, mc := range cr.MatchConditions {
				// cast the transforms slice to string slice
				var transformsOutput strings.Builder

				for x, t := range mc.Transforms {
					if x+1 == len(mc.Transforms) {
						if _, err := transformsOutput.WriteString(string(*t)); err != nil {
							logrus.Fatalf("builder failed to write string - err: %s", err.Error())
						}

						continue
					}

					if _, err := transformsOutput.WriteString(fmt.Sprintf("%s, ", string(*t))); err != nil {
						logrus.Fatalf("builder failed to write string - err: %s", err.Error())
					}
				}

				if mc.NegateCondition == nil {
					panic("negate condition not set")
				}

				table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
					{Text: dashIfEmptyString(mc.MatchVariable)},
					{Text: dashIfEmptyString(mc.Selector)},
					{Text: strconv.FormatBool(*mc.NegateCondition)},
					{Text: dashIfEmptyString(dashIfEmptyString(mc.Operator))},
					{Text: dashIfEmptyString(transformsOutput.String())},
					{Text: wrapMatchValues(mc.MatchValue, showFull)},
					{Text: ""},
				})
			}
			// separator
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: ""},
				{Text: ""},
				{Text: ""},
				{Text: ""},
				{Text: ""},
				{Text: ""},
				{Text: ""},
			})
		}
	}

	table.SetStyle(simpletable.StyleRounded)
	table.Println()

	// TODO: too much noise until i can check all operators correctly
	// d, err := HasDefaultDeny(policy)
	// if err != nil {
	// 	if logrus.IsLevelEnabled(logrus.DebugLevel) {
	// 		color.Red.Println("[ERROR] Failed to check if Policy has default deny.", err)
	// 		os.Exit(1)
	// 	}
	//
	// 	color.Red.Println("[ERROR] Failed to check if Policy has default deny. run with debug for error")
	// }
	//
	// if err == nil && !d {
	// 	color.Yellow.Println("[WARNING] Policy does not have default deny")
	// }
}

// getRuleConfig gets the configuration for a rule based on the current settings overlapping the defaults
func getRuleConfig(groupName string, manRuleDef *armfrontdoor.ManagedRuleDefinition, mrs armfrontdoor.ManagedRuleSet) ([]*armfrontdoor.ManagedRuleExclusion, *armfrontdoor.ActionType, string) {
	for x := range mrs.RuleGroupOverrides {
		if mrs.RuleGroupOverrides[x].RuleGroupName != nil && *mrs.RuleGroupOverrides[x].RuleGroupName == groupName {
			// found matching override for specific group so now find rule within the group
			for y := range mrs.RuleGroupOverrides[x].Rules {
				if *mrs.RuleGroupOverrides[x].Rules[y].RuleID != *manRuleDef.RuleID {
					continue
				}

				var exclusions []*armfrontdoor.ManagedRuleExclusion
				exclusions = mrs.RuleGroupOverrides[x].Rules[y].Exclusions

				var action *armfrontdoor.ActionType

				if mrs.RuleGroupOverrides[x].Rules[y].Action != nil {
					action = mrs.RuleGroupOverrides[x].Rules[y].Action
				}

				return exclusions, action, string(*mrs.RuleGroupOverrides[x].Rules[y].EnabledState)
			}
		}
	}

	// no rule override matching rule definition, so return default rule settings
	action := manRuleDef.DefaultAction
	enabled := string(*manRuleDef.DefaultState)

	return []*armfrontdoor.ManagedRuleExclusion{}, action, enabled
}

func getRuleGroupExclusions(groupName string, managedRuleSets []*armfrontdoor.ManagedRuleSet) []*armfrontdoor.ManagedRuleExclusion {
	for _, mrs := range managedRuleSets {
		mrs := mrs
		for _, rgo := range mrs.RuleGroupOverrides {
			if rgo.RuleGroupName != nil && *rgo.RuleGroupName == groupName {
				return rgo.Exclusions
			}
		}
	}

	return nil
}

type getManagedRuleInput struct {
	ruleID             string
	managedRuleSetList *armfrontdoor.ManagedRuleSetList
}

type getManagedRuleOutput struct {
	managedRuleGroup      string
	managedRuleOverride   *armfrontdoor.ManagedRuleOverride
	managedRuleSetType    string
	managedRuleSetVersion string
	managedRuleGroupName  string
}

func getManagedRule(in getManagedRuleInput) (mro getManagedRuleOutput) {
	for _, mrs := range in.managedRuleSetList.ManagedRuleSets {
		for _, rgo := range mrs.RuleGroupOverrides {
			for _, rule := range rgo.Rules {
				if rule.RuleID != nil && *rule.RuleID == in.ruleID {
					return getManagedRuleOutput{
						managedRuleGroup:      dashIfEmptyString(rgo.RuleGroupName),
						managedRuleOverride:   rule,
						managedRuleGroupName:  dashIfEmptyString(rgo.RuleGroupName),
						managedRuleSetType:    dashIfEmptyString(mrs.RuleSetType),
						managedRuleSetVersion: dashIfEmptyString(*mrs.RuleSetVersion),
					}
				}
			}
		}
	}

	return
}

func getManagedRulesetRows(managedRuleSetConfig armfrontdoor.ManagedRuleSet, mrsdl []*armfrontdoor.ManagedRuleSetDefinition) (cells [][]*simpletable.Cell) {
	mrsl := &armfrontdoor.ManagedRuleSetList{
		ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{&managedRuleSetConfig},
	}
	matchingDefinitions := getDefinitionMatchingExistingRuleSets(&getDefinitionsMatchingExistingRuleSetsInput{
		mrsdl:          mrsdl,
		mrsl:           mrsl,
		ruleSetType:    *managedRuleSetConfig.RuleSetType,
		ruleSetVersion: *managedRuleSetConfig.RuleSetVersion,
	})

	myBlueStyle := color.New(color.HiBlue)
	mrsTypeAndVersion := myBlueStyle.Sprintf("%s %s", *managedRuleSetConfig.RuleSetType, *managedRuleSetConfig.RuleSetVersion)

	var numRsExclusions int

	if managedRuleSetConfig.Exclusions != nil {
		numRsExclusions = len(managedRuleSetConfig.Exclusions)
	}

	cells = append(cells, []*simpletable.Cell{
		{Span: 2, Text: mrsTypeAndVersion},
		// RuleSetAction is in API spec but doesn't allow user to manage
		{Text: formatRuleAction(managedRuleSetConfig.RuleSetAction)},
		{Text: ""},
		{Text: strconv.Itoa(numRsExclusions)},
		{Text: ""},
	}, []*simpletable.Cell{
		{Text: "-----------"},
		{Text: "------------------------------------------------------------------------------------"},
		{Text: "--------"},
		{Text: "--------"},
		{Text: "----------"},
		{Text: "--------------------------"},
	})
	// record the previous group name so we know when to output row with exclusions count
	prevGroupName := ""

	for _, managedRuleSetDefinitionRuleGroup := range matchingDefinitions.RuleSetDefinition.Properties.RuleGroups {
		// TODO: Get number of RuleGroup exclusions
		rges := getRuleGroupExclusions(*managedRuleSetDefinitionRuleGroup.RuleGroupName,
			[]*armfrontdoor.ManagedRuleSet{&managedRuleSetConfig})
		numRges := len(rges)

		if prevGroupName != *managedRuleSetDefinitionRuleGroup.RuleGroupName {
			prevGroupName = *managedRuleSetDefinitionRuleGroup.RuleGroupName
			rowRGExclusions := color.Bold.Sprintf("%d (%d)", numRsExclusions+numRges, numRges)

			if len(rges) == 0 {
				rowRGExclusions = color.Bold.Sprintf("%d", numRsExclusions)
			}

			cells = append(cells, []*simpletable.Cell{
				{Text: ""},
				{Text: color.BgDarkGray.Sprintf("Rule Group Description: %s",
					TrimString(*managedRuleSetDefinitionRuleGroup.Description, trimDescriptionLength, "..."))},
				{Text: ""},
				{Text: ""},
				{Text: rowRGExclusions},
				{Text: color.Bold.Sprintf(*managedRuleSetDefinitionRuleGroup.RuleGroupName)},
			})
		}

		// loop through each rule in group, making those we have overrided and have exclusions for
		for _, rg := range managedRuleSetDefinitionRuleGroup.Rules {
			// check if rule has any overrides configured
			exclusions, ruleAction, ruleEnabledState := getRuleConfig(*managedRuleSetDefinitionRuleGroup.RuleGroupName, rg, managedRuleSetConfig)
			numRes := len(exclusions)

			ruleEnabledState = formatRuleEnabledState(ruleEnabledState, string(*rg.DefaultState))

			ruleActionOutput := formatRuleAction(ruleAction)

			rowRExclusions := fmt.Sprintf("%d", numRsExclusions+numRges+numRes)
			if numRes > 0 {
				// direct exclusions set, so output in brackets
				rowRExclusions = fmt.Sprintf("%d (%d)", numRsExclusions+numRges+numRes, numRes)
			}

			cells = append(cells, []*simpletable.Cell{
				{Text: *rg.RuleID},
				{Text: TrimString(*rg.Description, trimDescriptionLength, "...")},
				{Text: ruleActionOutput},
				{Text: ruleEnabledState},
				{Text: rowRExclusions},
				{Text: *managedRuleSetDefinitionRuleGroup.RuleGroupName},
			})
		}
	}

	return
}

func outputManagedRulesets(policy *armfrontdoor.WebApplicationFirewallPolicy, mrsdl []*armfrontdoor.ManagedRuleSetDefinition) {
	if ok, _ := HasRuleSets(policy); !ok {
		if *policy.SKU.Name == armfrontdoor.SKUNameStandardAzureFrontDoor {
			color.Bold.Println("Managed Rules: Cannot be viewed with Standard SKU")

			return
		}

		color.Bold.Println("Managed Rules: No rulesets enabled")

		return
	}

	fmt.Println()
	color.HiWhite.Println("Managed Rules")

	table := simpletable.New()
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Rule ID")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Rule Description")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Action")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Status")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Exclusions")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Rule Group")},
		},
	}

	for x, mrs := range policy.Properties.ManagedRules.ManagedRuleSets {
		mrs := mrs
		// if it's not the first row, then add separator row above
		if x != 0 {
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: "-----------"},
				{Text: "------------------------------------------------------------------------------------"},
				{Text: "--------"},
				{Text: "--------"},
				{Text: "----------"},
				{Text: "--------------------------"},
			})
		}

		table.Body.Cells = append(table.Body.Cells, getManagedRulesetRows(*mrs, mrsdl)...)
	}

	table.SetStyle(simpletable.StyleRounded)

	table.Println()

	// TODO: replace with call for a new function: NearMaxRulesLimit
	stats, err := getPolicyStats(policy, mrsdl)
	if err != nil {
		return
	}

	for x := range stats {
		if strings.Contains(stats[x].RuleSetType, "Bot") {
			continue
		}

		if stats[x].TotalExclusions >= maxExclusionLimitWarningThreshold && stats[x].TotalExclusions < maxExclusionLimit {
			color.Yellow.Printf("[WARNING] policy nearing maximum exclusion limit: %d/%d\n", stats[x].TotalExclusions, maxExclusionLimit)
		}

		if stats[x].TotalExclusions >= maxExclusionLimit {
			color.Red.Printf("[WARNING] policy has reached maximum exclusion limit: %d/%d\n", maxExclusionLimit, maxExclusionLimit)
		}
	}
}

func outputShadows(ruleShadows, ruleGroupShadows []shadow) {
	fmt.Println()

	color.HiWhite.Println("Exclusion Shadows")

	table := simpletable.New()
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprint("Shadow")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprint("Shadows")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprint("Exclusion Variable")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprint("Exclusion Operator")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprint("Exclusion Selector")},
		},
	}

	if len(ruleShadows) > 0 {
		for x := range ruleShadows {
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: fmt.Sprintf("%s: %s", printScope(ruleShadows[x].shadowType), ruleShadows[x].shadowName)},
				{Text: fmt.Sprintf("%s: %s", printScope(ruleShadows[x].shadowsType), ruleShadows[x].shadowsName)},
				{Text: string(*ruleShadows[x].exclusion.MatchVariable)},
				{Text: string(*ruleShadows[x].exclusion.SelectorMatchOperator)},
				{Text: *ruleShadows[x].exclusion.Selector},
			})
		}
	}

	if len(ruleGroupShadows) > 0 {
		for x := range ruleGroupShadows {
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: fmt.Sprintf("%s: %s", printScope(ruleGroupShadows[x].shadowType), ruleGroupShadows[x].shadowName)},
				{Text: fmt.Sprintf("%s: %s", printScope(ruleGroupShadows[x].shadowsType), ruleGroupShadows[x].shadowsName)},
				{Text: string(*ruleGroupShadows[x].exclusion.MatchVariable)},
				{Text: string(*ruleGroupShadows[x].exclusion.SelectorMatchOperator)},
				{Text: *ruleGroupShadows[x].exclusion.Selector},
			})
		}
	}

	table.SetStyle(simpletable.StyleRounded)
	table.Println()
}

func printScope(scope string) string {
	switch scope {
	case ScopeRule:
		return "Rule"
	case ScopeRuleGroup:
		return "Rule Group"
	case ScopeRuleSet:
		return "Rule Set"
	default:
		return ""
	}
}

func outputPolicyRuleSetStats(statsList *[]RuleSetStatsOutput) {
	fmt.Println()
	color.Bold.Println("Stats")

	table := simpletable.New()
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("item")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("count (limit)")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("")},
		},
	}

	statsL := *statsList
	for x := range statsL {
		table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
			{Span: 3, Text: color.HiBlue.Sprintf("%s_%s",
				statsL[x].RuleSetType,
				statsL[x].RuleSetVersion)},
		}, []*simpletable.Cell{
			{Text: color.HiWhite.Sprint("----------------")},
			{Text: color.HiWhite.Sprint("---------------")},
			{Text: color.HiWhite.Sprint("-------------")},
		}, []*simpletable.Cell{
			{Text: color.HiWhite.Sprint("Rules")},
			{Text: color.HiWhite.Sprintf("%d", statsL[x].Rules)},
			{Text: color.HiWhite.Sprint("-")},
		}, []*simpletable.Cell{
			{Text: "Enabled"},
			{Text: strconv.Itoa(statsL[x].RulesEnabled)},
			{Text: color.HiWhite.Sprint("-")},
		}, []*simpletable.Cell{
			{Text: "Disabled"},
			{Text: strconv.Itoa(statsL[x].RulesDisabled)},
			{Text: color.HiWhite.Sprint("-")},
		}, []*simpletable.Cell{
			{Text: "Allow"},
			{Text: strconv.Itoa(statsL[x].AllowTotal)},
			{Text: color.HiWhite.Sprint("-")},
		}, []*simpletable.Cell{
			{Text: "Block"},
			{Text: strconv.Itoa(statsL[x].BlockTotal)},
			{Text: "-"},
		}, []*simpletable.Cell{
			{Text: "Log"},
			{Text: strconv.Itoa(statsL[x].LogTotal)},
			{Text: "-"},
		}, []*simpletable.Cell{
			{Text: "Redirect"},
			{Text: strconv.Itoa(statsL[x].AllowTotal)},
			{Text: "-"},
		})

		// bot rulesets don't support exclusions, so only output for other ruleset types
		if !strings.Contains(statsL[x].RuleSetType, "Bot") {
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: color.HiWhite.Sprint("----------------")},
				{Text: color.HiWhite.Sprint("---------------")},
				{Text: "-------------"},
			}, []*simpletable.Cell{
				{Text: color.HiWhite.Sprint("Exclusions")},
				{Text: color.HiWhite.Sprintf("%s (%d)", strconv.Itoa(statsL[x].TotalExclusions), maxExclusionLimit)},
				{Text: "-"},
			}, []*simpletable.Cell{
				{Text: "Rule set scope"},
				{Text: strconv.Itoa(statsL[x].RuleSetScopeExclusionsTotal)},
				{Text: "-"},
			}, []*simpletable.Cell{
				{Text: "Rule group scope"},
				{Text: strconv.Itoa(statsL[x].RuleGroupScopeExclusionsTotal)},
				{Text: "-"},
			}, []*simpletable.Cell{
				{Text: "Rule scope"},
				{Text: strconv.Itoa(statsL[x].RuleScopeExclusionsTotal)},
				{Text: "-"},
			})
		}

		if x == 0 {
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: color.HiWhite.Sprint("----------------")},
				{Text: color.HiWhite.Sprint("---------------")},
				{Text: "-------------"},
			})
		}
	}

	table.SetStyle(simpletable.StyleRounded)

	table.Println()
}

// formatPolicyProvisioningState accepts a waf Policy's provisioning state and returns a colored text representation
func formatPolicyProvisioningState(provisioningState *string) string {
	if provisioningState == nil {
		logrus.Errorf("provisioning state isn't defined")
		return "-"
	}

	if *provisioningState == "Succeeded" {
		return color.Green.Sprint("Succeeded")
	}

	return color.Yellow.Sprint(*provisioningState)
}

// formatRequestBodyCheck(policy.Properties.PolicySettings.RequestBodyCheck))

func formatRedirectURL(url *string) string {
	if url == nil {
		return "-"
	}

	return *url
}

func formatRequestBodyCheck(check *armfrontdoor.PolicyRequestBodyCheck) string {
	if check == nil {
		return "-"
	}

	switch *check {
	case armfrontdoor.PolicyRequestBodyCheckEnabled:
		return color.Green.Sprint(armfrontdoor.PolicyRequestBodyCheckEnabled)
	case armfrontdoor.PolicyRequestBodyCheckDisabled:
		return color.Red.Sprint(armfrontdoor.PolicyRequestBodyCheckDisabled)
	default:
		logrus.Debugf("unexpected policy request body check %s", *check)
		return "-"
	}
}

func formatCustomBlockResponseStatusCode(mode *int32) string {
	if mode == nil {
		logrus.Debugf("custom block response status code not defined")
		return "-"
	}

	return strconv.Itoa(int(*mode))
}

func formatCustomBlockResponseBody(mode *string) string {
	if mode == nil || *mode == "" {
		return color.Yellow.Sprint("Undefined")
	}

	return color.Green.Sprint("Defined")
}

func formatPolicyMode(mode *armfrontdoor.PolicyMode) string {
	if mode == nil {
		logrus.Errorf("policy mode not defined")
		return "-"
	}

	switch *mode {
	case armfrontdoor.PolicyModePrevention:
		return color.Green.Sprint(armfrontdoor.PolicyModePrevention)
	case armfrontdoor.PolicyModeDetection:
		return color.Yellow.Sprint(armfrontdoor.PolicyModeDetection)
	default:
		logrus.Errorf("unexpected policy mode '%s'", *mode)

		return "-"
	}
}

func formatPolicyEnabledState(enabledState *armfrontdoor.PolicyEnabledState) string {
	if enabledState == nil {
		logrus.Errorf("policy enabled state not defined")
		return "-"
	}

	switch *enabledState {
	case armfrontdoor.PolicyEnabledStateEnabled:
		return color.Green.Sprint(armfrontdoor.PolicyEnabledStateEnabled)
	case armfrontdoor.PolicyEnabledStateDisabled:
		return color.Red.Sprint(armfrontdoor.PolicyEnabledStateEnabled)
	default:
		logrus.Errorf("unexpected policy enabled state '%s'", *enabledState)

		return "-"
	}
}

// formatPolicyResourceState accepts a waf Policy's resource state and returns a colored text representation
func formatPolicyResourceState(resourceState *armfrontdoor.PolicyResourceState) string {
	if resourceState == nil {
		logrus.Errorf("resource state not defined")
		return "-"
	}

	switch *resourceState {
	case armfrontdoor.PolicyResourceStateEnabled:
		return color.Green.Sprint(*resourceState)
	case armfrontdoor.PolicyResourceStateEnabling:
		return color.BgGreen.Sprint(*resourceState)
	case armfrontdoor.PolicyResourceStateCreating:
		return color.BgGreen.Sprint(*resourceState)
	case armfrontdoor.PolicyResourceStateDisabled:
		return color.Red.Sprint(*resourceState)
	case armfrontdoor.PolicyResourceStateDisabling:
		return color.BgRed.Sprint(*resourceState)
	case armfrontdoor.PolicyResourceStateDeleting:
		return color.BgRed.Sprint(*resourceState)
	case "":
		return ""
	default:
		logrus.Errorf("unexpected provisioning state '%s'", *resourceState)
	}

	return ""
}

type OutputManagedRuleExclusionsTableInput struct {
	narrowestScope                 string
	ruleDefinition                 *armfrontdoor.ManagedRuleDefinition
	groupDefinition                *armfrontdoor.ManagedRuleGroupDefinition
	setDefinition                  *armfrontdoor.ManagedRuleSetDefinition
	ruleOverride                   *armfrontdoor.ManagedRuleOverride
	groupExclusions, setExclusions []*armfrontdoor.ManagedRuleExclusion
}

func OutputManagedRuleExclusionsTable(in *OutputManagedRuleExclusionsTableInput) {
	seperatorRow := []*simpletable.Cell{
		{Text: "----"},
		{Text: "-----------------------"},
		{Text: "----------"},
		{Text: "----------"},
	}
	table := simpletable.New()
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Scope")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Match variable")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Operator")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Selector")},
		},
	}

	// TODO: move to a getRuleExclusionsRows func
	if in.narrowestScope == ScopeRule {
		if in.ruleOverride == nil || len(in.ruleOverride.Exclusions) == 0 {
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: "Rule"},
				{Text: "none found", Span: 3},
			})
		} else {
			for _, exclusion := range in.ruleOverride.Exclusions {
				table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
					{Text: "Rule"},
					{Text: string(*exclusion.MatchVariable)},
					{Text: string(*exclusion.SelectorMatchOperator)},
					{Text: *exclusion.Selector},
				})
			}
		}

		table.Body.Cells = append(table.Body.Cells, seperatorRow)
	}

	// TODO: move to a getRuleGroupExclusionsRows func
	if slices.Contains([]string{ScopeRule, ScopeRuleGroup}, in.narrowestScope) {
		if len(in.groupExclusions) == 0 {
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: "RuleGroup"},
				{Text: "none found", Span: 3},
			})
		} else {
			for _, exclusion := range in.groupExclusions {
				table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
					{Text: "RuleGroup"},
					{Text: string(*exclusion.MatchVariable)},
					{Text: string(*exclusion.SelectorMatchOperator)},
					{Text: *exclusion.Selector},
				})
			}
		}

		table.Body.Cells = append(table.Body.Cells, seperatorRow)
	}

	if len(in.setExclusions) == 0 {
		table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
			{Text: "Set"},
			{Text: "none found", Span: 3},
		})
	} else {
		for _, exclusion := range in.setExclusions {
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: "Set"},
				{Text: string(*exclusion.MatchVariable)},
				{Text: string(*exclusion.SelectorMatchOperator)},
				{Text: *exclusion.Selector},
			})
		}
	}

	table.SetStyle(simpletable.StyleRounded)

	table.Println()
}

func OutputManagedRuleSetExclusionsTable(in *OutputManagedRuleExclusionsTableInput) {
	table := simpletable.New()

	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Match variable")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Operator")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Selector")},
		},
	}

	if len(in.setExclusions) == 0 {
		table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
			{Text: "none found", Span: 3},
		})
	} else {
		for _, exclusion := range in.setExclusions {
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: string(*exclusion.MatchVariable)},
				{Text: string(*exclusion.SelectorMatchOperator)},
				{Text: *exclusion.Selector},
			})
		}
	}

	table.SetStyle(simpletable.StyleRounded)

	table.Println()
}

func OutputPolicyMetaData(policy *armfrontdoor.WebApplicationFirewallPolicy) {
	rid := config.ParseResourceID(*policy.ID)
	fmt.Printf("\n%s:%s%s (hash: %s)\n", color.Bold.Sprint("Policy Name"), spaces(9), rid.Name, computeAdler32(*policy.ID))
	fmt.Printf("%s:%s%s\n", color.Bold.Sprint("SKU"), spaces(17), *policy.SKU.Name)
	fmt.Printf("%s:%s%s\n", color.Bold.Sprint("Resource Group"), spaces(6), rid.ResourceGroup)
	fmt.Printf("%s:%s%s\n", color.Bold.Sprint("Subscription"), spaces(8), rid.SubscriptionID)
	fmt.Printf("\n%s:%s%s\n", color.Bold.Sprint("Provisioning State"), spaces(2), formatPolicyProvisioningState(policy.Properties.ProvisioningState))
	fmt.Printf("%s:%s%s\n", color.Bold.Sprint("Resource State"), spaces(6), formatPolicyResourceState(policy.Properties.ResourceState))
	fmt.Printf("%s:%s%s\n", color.Bold.Sprint("Enabled State"), spaces(7), formatPolicyEnabledState(policy.Properties.PolicySettings.EnabledState))
	fmt.Printf("%s:%s%s\n", color.Bold.Sprint("Mode"), spaces(16), formatPolicyMode(policy.Properties.PolicySettings.Mode))
	fmt.Printf("%s:%s%s\n", color.Bold.Sprint("Redirect URL"), spaces(8), formatRedirectURL(policy.Properties.PolicySettings.RedirectURL))
	fmt.Printf("\n%s:%s%s\n", color.Bold.Sprint("Custom Block Response Status Code"), spaces(2), formatCustomBlockResponseStatusCode(policy.Properties.PolicySettings.CustomBlockResponseStatusCode))
	fmt.Printf("%s:%s%s\n", color.Bold.Sprint("Custom Block Response Body"), spaces(9), formatCustomBlockResponseBody(policy.Properties.PolicySettings.CustomBlockResponseBody))
	fmt.Printf("%s:%s%s\n", color.Bold.Sprint("Request Body Check"), spaces(17), formatRequestBodyCheck(policy.Properties.PolicySettings.RequestBodyCheck))
}

func spaces(num int) string {
	return strings.Repeat(" ", num)
}

func OutputManagedRuleExclusions(in *OutputManagedRuleInput) {
	OutputPolicyMetaData(in.Policy)
	fmt.Println()

	// TODO: Order by Scope (Rule, RuleGroup, Set) and then by Match Variable
	fmt.Printf("%s:%s%s\n", color.Bold.Sprint("Rule Set"), spaces(5), *in.RuleSetDefinition.Name)
	fmt.Printf("%s:%s%s (%s)\n", color.Bold.Sprint("Rule Group"), spaces(3), *in.RuleGroupDefinition.RuleGroupName, *in.RuleGroupDefinition.Description)
	fmt.Printf("%s:%s%s (%s)\n", color.Bold.Sprint("Rule Name"), spaces(4), *in.RuleDefinition.RuleID, *in.RuleDefinition.Description)
	// if a rule wasn't passed, then get the default
	ruleAction := in.RuleDefinition.DefaultAction
	if in.Rule != nil {
		ruleAction = in.Rule.Action
	}

	fmt.Printf("%s:%s%s \n", color.Bold.Sprint("Rule Action"), spaces(2), formatRuleAction(ruleAction))

	ruleEnabledState := *in.RuleDefinition.DefaultState
	if in.Rule != nil {
		ruleEnabledState = *in.Rule.EnabledState
	}

	fmt.Printf("%s:%s%s \n", color.Bold.Sprint("Rule Status"), spaces(2), formatRuleEnabledState(string(ruleEnabledState), "-"))
	color.Bold.Printf("\nExclusions\n")

	OutputManagedRuleExclusionsTable(&OutputManagedRuleExclusionsTableInput{
		narrowestScope:  ScopeRule,
		ruleDefinition:  in.RuleDefinition,
		groupDefinition: in.RuleGroupDefinition,
		setDefinition:   in.RuleSetDefinition,
		ruleOverride:    in.Rule,
		groupExclusions: in.RuleGroupExclusions,
		setExclusions:   in.RuleSetExclusions,
	})
}

func OutputManagedRuleGroupExclusions(in *OutputManagedRuleInput) {
	OutputPolicyMetaData(in.Policy)
	fmt.Println()

	// TODO: Order by Scope (Rule, RuleGroup, Set) and then by Match Variable
	fmt.Printf("%s:     %s\n", color.Bold.Sprint("Rule Set"), *in.RuleSetDefinition.Name)
	fmt.Printf("%s:   %s (%s)\n", color.Bold.Sprint("Rule Group"), *in.RuleGroupDefinition.RuleGroupName, *in.RuleGroupDefinition.Description)
	color.Bold.Printf("\nExclusions\n")
	OutputManagedRuleExclusionsTable(&OutputManagedRuleExclusionsTableInput{
		narrowestScope:  ScopeRuleGroup,
		ruleDefinition:  in.RuleDefinition,
		groupDefinition: in.RuleGroupDefinition,
		setDefinition:   in.RuleSetDefinition,
		ruleOverride:    in.Rule,
		groupExclusions: in.RuleGroupExclusions,
		setExclusions:   in.RuleSetExclusions,
	})
}

func OutputManagedRuleSetExclusions(in *OutputManagedRuleInput) {
	OutputPolicyMetaData(in.Policy)
	fmt.Println()

	// TODO: Order by Scope (Rule, RuleGroup, Set) and then by Match Variable
	fmt.Printf("%s:     %s\n", color.Bold.Sprint("Rule Set"), *in.RuleSetDefinition.Name)
	color.Bold.Printf("\nExclusions\n")
	OutputManagedRuleSetExclusionsTable(&OutputManagedRuleExclusionsTableInput{
		narrowestScope:  ScopeRuleGroup,
		ruleDefinition:  in.RuleDefinition,
		groupDefinition: in.RuleGroupDefinition,
		setDefinition:   in.RuleSetDefinition,
		setExclusions:   in.RuleSetExclusions,
	})
}

type OutputPolicyInput struct {
	policy                                                    *armfrontdoor.WebApplicationFirewallPolicy
	rsds                                                      []*armfrontdoor.ManagedRuleSetDefinition
	showFull, showCustom, showManaged, showStats, showShadows bool
}

func OutputPolicy(input OutputPolicyInput) {
	OutputPolicyMetaData(input.policy)

	fmt.Println()

	if !input.showManaged {
		outputCustomRules(input.policy, input.showFull)
	}

	defaultRuleSet := getDefaultRuleSet(input.policy)

	if !input.showCustom {
		outputManagedRulesets(input.policy, input.rsds)
	}

	if input.showStats {
		stats, err := getPolicyStats(input.policy, input.rsds)
		if err != nil {
			return
		}

		outputPolicyRuleSetStats(&stats)
	}

	if input.showShadows {
		ruleShadows, groupShadows := getShadowsFromRuleSet(defaultRuleSet)
		if len(ruleShadows) == 0 && len(groupShadows) == 0 {
			fmt.Println("no shadows found")

			return
		}

		outputShadows(ruleShadows, groupShadows)
	}
}

func getDefaultRuleSet(policy *armfrontdoor.WebApplicationFirewallPolicy) *armfrontdoor.ManagedRuleSet {
	for x := range policy.Properties.ManagedRules.ManagedRuleSets {
		if strings.Contains(*policy.Properties.ManagedRules.ManagedRuleSets[x].RuleSetType, "DefaultRuleSet") {
			return policy.Properties.ManagedRules.ManagedRuleSets[x]
		}
	}

	return nil
}

// dashIfEmptyString returns the string value (or value pointed to) or a hyphen if the pointer is nil or value empty
func dashIfEmptyString(val interface{}) string {
	switch v := val.(type) {
	case nil:
		return "-"
	case *string:
		if v != nil && len(*v) > 0 {
			return *v
		}
	case string:
		if len(v) > 0 {
			return v
		}
	case *armfrontdoor.MatchVariable:
		return string(*v)
	case *armfrontdoor.Operator:
		return string(*v)
	default:
		return "-"
	}

	return "-"
}

func processMatchVal(s string) (result string, isURL, isIPv4, isIPv6, isGeo bool) {
	if len(s) <= geoCodeMaxLen {
		isGeo = true
	}

	isURL = strings.HasPrefix(s, "http")
	isIPv4 = IsIPv4(s)
	isIPv6 = IsIPv6(s)

	maxColWidth := maxColumnWidth
	if len(s) > maxColWidth && isURL {
		result = fmt.Sprintf("%s...", s[:shortURLLength])
	} else {
		result = s
	}

	return
}

func handleGeoValue(builder *strings.Builder, val string, valsWritten *int) {
	if *valsWritten == valsPerGeoLine {
		if _, err := builder.WriteString(fmt.Sprintf("%s\n", val)); err != nil {
			logrus.Fatalf("builder failed to write output - err: %s", err.Error())
		}

		*valsWritten = 0
	} else {
		if _, err := builder.WriteString(fmt.Sprintf("%s, ", val)); err != nil {
			logrus.Fatalf("builder failed to write output - err: %s", err.Error())
		}

		(*valsWritten)++
	}
}

func handleURLValue(builder *strings.Builder, val string, prevType *string) {
	if _, err := builder.WriteString(fmt.Sprintf("%s\n", val)); err != nil {
		logrus.Fatalf("builder failed to write string - %s", err.Error())
	}

	*prevType = ""
}

func handleIPv4Value(builder *strings.Builder, val string, prevType *string, valsWritten *int, prevLen, nextLen int) {
	switch *prevType {
	case "":
		if _, err := builder.WriteString(fmt.Sprintf("%s, ", val)); err != nil {
			logrus.Fatalf("builder failed to write string - %s", err.Error())
		}

		(*valsWritten)++

		*prevType = "ipv4"
	case "ipv4":
		switch {
		case *valsWritten == 2:
			if _, err := builder.WriteString(fmt.Sprintf("%s\n", val)); err != nil {
				logrus.Fatalf("builder failed to write string - %s", err.Error())
			}

			*valsWritten = 0

			*prevType = ""
		case *valsWritten == 1 && (prevLen+len(val)+nextLen) > lineLengthLimit:
			if _, err := builder.WriteString(fmt.Sprintf("%s\n", val)); err != nil {
				logrus.Fatalf("builder failed to write string - %s", err.Error())
			}

			*valsWritten = 0

			*prevType = ""
		default:
			if _, err := builder.WriteString(fmt.Sprintf("%s, ", val)); err != nil {
				logrus.Fatalf("builder failed to write string - %s", err.Error())
			}

			(*valsWritten)++

			*prevType = "ipv4"
		}
	case "ipv6":
		switch {
		case *valsWritten == 2:
			if _, err := builder.WriteString(fmt.Sprintf("%s\n", val)); err != nil {
				logrus.Fatalf("builder failed to write string - err: %s", err.Error())
			}

			*valsWritten = 0

			*prevType = ""
		case *valsWritten == 1 && (prevLen+len(val)+nextLen) > lineLengthLimit:
			if _, err := builder.WriteString(fmt.Sprintf("%s\n", val)); err != nil {
				logrus.Fatalf("builder failed to write string - err: %s", err.Error())
			}

			*valsWritten = 0

			*prevType = ""
		default:
			if _, err := builder.WriteString(fmt.Sprintf("%s, ", val)); err != nil {
				logrus.Fatalf("builder failed to write string - err: %s", err.Error())
			}

			(*valsWritten)++

			*prevType = "ipv4"
		}
	default:
		logrus.Errorf("unexpected prev type '%s'", *prevType)
	}
}

func handleIPv6Value(builder *strings.Builder, val string, prevType *string, valsWritten *int, prevLen, nextLen int) {
	switch *prevType {
	case "":
		if _, err := builder.WriteString(fmt.Sprintf("%s, ", val)); err != nil {
			logrus.Fatalf("builder failed to write string - err: %s", err.Error())
		}

		(*valsWritten)++

		*prevType = "ipv6"
	case "ipv4":
		switch {
		case *valsWritten == 1 && (prevLen+len(val)+nextLen) > lineLengthLimit:
			if _, err := builder.WriteString(fmt.Sprintf("%s\n", val)); err != nil {
				logrus.Fatalf("builder failed to write string - err: %s", err.Error())
			}

			*valsWritten = 0

			*prevType = ""
		case *valsWritten == 2:
			if _, err := builder.WriteString(fmt.Sprintf("%s\n", val)); err != nil {
				logrus.Fatalf("builder failed to write string - err: %s", err.Error())
			}

			*valsWritten = 0

			*prevType = ""
		default:
			if _, err := builder.WriteString(fmt.Sprintf("%s, ", val)); err != nil {
				logrus.Fatalf("builder failed to write string - err: %s", err.Error())
			}

			(*valsWritten)++

			*prevType = "ipv6"
		}
	case "ipv6":
		switch {
		case *valsWritten == 1 && (prevLen+len(val)+nextLen) > lineLengthLimit:
			if _, err := builder.WriteString(fmt.Sprintf("%s\n", val)); err != nil {
				logrus.Fatalf("builder failed to write string - err: %s", err.Error())
			}

			*valsWritten = 0

			*prevType = ""
		case *valsWritten == 2:
			if _, err := builder.WriteString(fmt.Sprintf("%s\n", val)); err != nil {
				logrus.Fatalf("builder failed to write string - err: %s", err.Error())
			}

			*valsWritten = 0

			*prevType = ""
		default:
			if _, err := builder.WriteString(fmt.Sprintf("%s, ", val)); err != nil {
				logrus.Fatalf("builder failed to write string - err: %s", err.Error())
			}

			(*valsWritten)++

			*prevType = "ipv6"
		}
	default:
		logrus.Errorf("unexpected prev type '%s'", *prevType)
	}
}

// wrapMatchValues accepts a slice of strings and returns a single comma/line-break separated representation
// urls have one line each
// ipv4 addresses are comma separated, with three per line
// ipv6 are comma separated with two per line
// one ipv4 plus one ipv6 are shown on a single line
// one ipv6 plus one ipv4 are shown on a single line
// values of over <column size> are shortened
func wrapMatchValues(mvs []*string, showFull bool) string {
	builder := strings.Builder{}

	var prevType string
	var valsWritten int

	for i, mv := range mvs {
		val, isURL, isIPv4, isIPv6, isGeo := processMatchVal(*mv)
		prevLen := 0
		if i > 0 {
			prevLen = len(*mvs[i-1])
		}
		nextLen := 0
		if i < len(mvs)-1 {
			nextLen = len(*mvs[i+1])
		}
		switch {
		case isGeo:
			handleGeoValue(&builder, val, &valsWritten)
		case isURL:
			handleURLValue(&builder, val, &prevType)
		case isIPv4:
			handleIPv4Value(&builder, val, &prevType, &valsWritten, prevLen, nextLen)
		case isIPv6:
			handleIPv6Value(&builder, val, &prevType, &valsWritten, prevLen, nextLen)
		default:
			logrus.Errorf("unknown type for %s", val)
		}
		if i+1 == MaxMatchValuesOutput && !showFull {
			if _, err := builder.WriteString(fmt.Sprintf("... %d remaining", len(mvs)-(i+1))); err != nil {
				logrus.Fatalf("builder failed to write string - err: %s", err.Error())
			}
			break
		}
	}
	return strings.TrimRight(builder.String(), ", ")
}

func DisplayStringDiffWithDiffTool(orig, updated string) error {
	origPath, err := os.CreateTemp("", "*")
	if err != nil {
		return err
	}

	defer os.Remove(origPath.Name())

	newPath, err := os.CreateTemp("", "*")
	if err != nil {
		return err
	}

	defer os.Remove(newPath.Name())

	_, err = origPath.WriteString(orig)
	if err != nil {
		return err
	}

	_, err = newPath.WriteString(updated)
	if err != nil {
		return err
	}

	diffBinary := findexec.Find("diff", "")
	if diffBinary == "" {
		return errors2.New("failed to find compare binary")
	}

	// #nosec
	cmd := exec.Command(
		diffBinary,
		"-u",
		origPath.Name(),
		newPath.Name(),
	)

	out, oErr := cmd.CombinedOutput()

	var exitCode int

	if oErr != nil {
		if exitError, ok := oErr.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		}
	}

	if exitCode == diffErrorExitCode {
		return fmt.Errorf("failed to compare policies")
	}

	fmt.Println(string(out))

	return err
}

func TrimString(in string, maxLen int, suffix string) string {
	if len(in) <= maxLen {
		return in
	}

	// if suffix is equal or longer than input, then return first x chars of input
	// 	require.Equal(t, "hello", TrimString("hello", 4, "..."))
	if len(suffix) >= maxLen {
		return in[:maxLen]
	}

	// input is longer than max len and suffix is less than maxlen
	// trim input to max length
	p := in[:maxLen]
	// suffix can be output in Full, without being the only output, then return suffix and first x chars of input, up to max len
	if len(suffix) < len(p) {
		return fmt.Sprintf("%s%s", p[:maxLen-len(suffix)], suffix)
	}

	// suffix cannot be output in Full without being only output, so return output up to max length, without suffix
	return p
}

type ListPoliciesInput struct {
	SubscriptionID, AppVersion string
	Max                        int
	Full                       bool
}

func ListPolicies(in ListPoliciesInput) error {
	s := session.New()

	o, err := GetAllPolicies(s, GetWrappedPoliciesInput{
		SubscriptionID:    in.SubscriptionID,
		AppVersion:        in.AppVersion,
		Max:               in.Max,
		FilterResourceIDs: nil,
	})
	if err != nil {
		return err
	}

	if len(o) == 0 {
		logrus.Infof("no policies found")

		return nil
	}

	// sort by resource id
	sort.Slice(o, func(i, j int) bool { return *o[i].ID < *o[j].ID })

	fmt.Println()

	color.Bold.Print("Web Application Firewall Policies\nSubscription: ")

	fmt.Println(in.SubscriptionID)

	table := simpletable.New()

	if in.Full {
		// if Full output is required, display resource id and hash
		table.Header = &simpletable.Header{
			Cells: []*simpletable.Cell{
				{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("resource id")},
				{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("hash")},
			},
		}
	} else {
		table.Header = &simpletable.Header{
			Cells: []*simpletable.Cell{
				{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("resource group")},
				{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("name")},
				{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("hash")},
			},
		}
	}

	for _, p := range o {
		var r []*simpletable.Cell

		rID := config.ParseResourceID(*p.ID)

		if in.Full {
			r = []*simpletable.Cell{
				{Text: rID.Raw},
				{Text: computeAdler32(*p.ID)},
			}
		} else {
			r = []*simpletable.Cell{
				{Text: rID.ResourceGroup},
				{Text: rID.Name},
				{Text: computeAdler32(*p.ID)},
			}
		}

		table.Body.Cells = append(table.Body.Cells, r)
	}

	table.Println()

	return nil
}
