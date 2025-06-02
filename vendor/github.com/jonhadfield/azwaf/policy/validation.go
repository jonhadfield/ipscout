package policy

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/sirupsen/logrus"
)

func commonCLIInputValidation(subscriptionID, policyID string) error {
	funcName := GetFunctionName()

	if err := ValidateResourceID(policyID, false); err != nil {
		return fmt.Errorf(err.Error(), funcName)
	}

	// unlike a raw policy ID, a resource id hash doesn't contain a subscription id, so one needs to be provided
	// in order to find a matching resource using the SDK
	if IsRIDHash(policyID) && subscriptionID == "" {
		return fmt.Errorf("%s - using a policy hash requires a subscription id", funcName)
	}

	if err := validateSubscriptionID(subscriptionID); err != nil {
		return err
	}

	return nil
}

func (in ListPoliciesInput) Validate() error {
	if err := validateSubscriptionID(in.SubscriptionID); err != nil {
		return err
	}

	if in.Max == 0 {
		return fmt.Errorf("%s - invalid maximum number of policies to return", GetFunctionName())
	}

	return nil
}

func validateSubscriptionID(subscriptionID string) error {
	funcName := GetFunctionName()

	if subscriptionID == "" {
		return errors.New("subscription-id is required")
	}

	if !slices.Contains([]int{36, 38}, len(subscriptionID)) {
		return fmt.Errorf("%s - subscription-id has incorrect length", funcName)
	}

	if subscriptionID[8] != '-' || subscriptionID[13] != '-' || subscriptionID[18] != '-' || subscriptionID[23] != '-' {
		return fmt.Errorf("%s - subscription-id is invalid format", funcName)
	}

	return nil
}

func (in *ShowPolicyInput) Validate() error {
	if in.Custom && in.Managed && !in.Stats {
		return fmt.Errorf("%s - at least one of --custom, --managed and --stats is required", GetFunctionName())
	}

	return nil
}

func containsStr(items interface{}, str string) bool {
	var strs []string

	switch v := items.(type) {
	case []*string:
		strs = deRefStrs(v)
	default:
		logrus.Errorf("unhandled type for comparison %s", reflect.TypeOf(items).String())
	}

	return slices.Contains(strs, str)
}

func MatchValuesHasMatchAll(mvs []*string, matchVariable armfrontdoor.MatchVariable, operator armfrontdoor.Operator) (res bool) {
	switch operator {
	case armfrontdoor.OperatorGeoMatch:
		// unable to list all available to be able to determine if it's a match all
		switch matchVariable {
		case armfrontdoor.MatchVariableRemoteAddr:
			// unable to list all available to be able to determine if it's a match all
			logrus.Tracef("unable to list all available to be able to determine if it's a match all")
		case armfrontdoor.MatchVariableSocketAddr:
			// unable to list all available to be able to determine if it's a match all
			logrus.Tracef("unable to list all available to be able to determine if it's a match all")
		}
	case armfrontdoor.OperatorIPMatch:
		switch matchVariable {
		case armfrontdoor.MatchVariableRemoteAddr:
			if containsStr(mvs, "0.0.0.0/0") || containsStr(mvs, "::/0") || containsStr(mvs, "0000:0000:0000:0000:0000:0000:0000:0000/0") {
				return true
			}
		case armfrontdoor.MatchVariableSocketAddr:
			if containsStr(mvs, "0.0.0.0/0") || containsStr(mvs, "::/0") || containsStr(mvs, "0000:0000:0000:0000:0000:0000:0000:0000/0") {
				return true
			}
		}
	}

	logrus.Debugf("%s | match variable %s with operator %s not supported for checking if match-all is true",
		GetFunctionName(), matchVariable, operator)

	return
}

func MatchConditionHasDefaultUnknown(mc *armfrontdoor.MatchCondition) (result bool) {
	// if match condition doesn't negate, and the match values contains a match all, then true
	hasMatchAll := MatchValuesHasMatchAll(mc.MatchValue, *mc.MatchVariable, *mc.Operator)

	if !*mc.NegateCondition && hasMatchAll {
		return true
	}

	if *mc.NegateCondition && !hasMatchAll {
		return true
	}

	return
}

func CustomRuleHasDefaultDeny(c *armfrontdoor.CustomRule) (defaultDeny bool) {
	// if all match conditions have "if not... then deny" (other than a single rule saying if not 0.0.0.0/0 then deny) then they do
	// if a rule only has "if ip 0.0.0.0/0 then deny" then true
	if *c.Action != armfrontdoor.ActionTypeBlock {
		return
	}

	var du bool

	// check if any match condition has a default unknown
	for _, mc := range c.MatchConditions {
		du = MatchConditionHasDefaultUnknown(mc)

		if du {
			return true
		}
	}

	return
}

// ValidateResourceID will tokenise and check the format is valid
// 'extended' parameter is used to indicate if pipe separated value follows id
func ValidateResourceID(rawID string, extended bool) error {
	// check if hash was provided instead
	if !extended && IsRIDHash(rawID) {
		return nil
	}

	if !strings.Contains(rawID, "/") {
		return fmt.Errorf("resource id has invalid format")
	}

	// start checks for explicit resource id
	if len(strings.Split(rawID, "/")) != 9 {
		return fmt.Errorf("resource id has incorrect number of sections")
	}

	isValid := regexp.MustCompile(
		`(?i)/subscriptions/(.+?)/resourcegroups/(.+?)/providers/(.+?)/(.+?)/(.+)`).MatchString

	if !isValid(rawID) {
		return fmt.Errorf("resource id has invalid format")
	}

	if !extended && strings.Contains(rawID, "|") {
		return fmt.Errorf("resource id has invalid format")
	}

	if extended {
		if !strings.Contains(rawID, "|") {
			return fmt.Errorf("invalid format for extended resource id")
		}
	}

	return nil
}

func ValidateResourceIDs(ids []string) error {
	for _, id := range ids {
		if err := ValidateResourceID(id, false); err != nil {
			return fmt.Errorf("%w: %s", err, id)
		}
	}

	return nil
}

func ipMatchValuesWithPublicInternet() []*string {
	return []*string{
		toPtr("1.1.1.1/32"),
		toPtr("2.2.2.2/32"),
		toPtr("0.0.0.0/0"),
		toPtr("4.4.4.4/32"),
	}
}

func ipMatchValuesNoPublicInternet() []*string {
	return []*string{
		toPtr("5.5.5.5/32"),
		toPtr("52.0.0.0/24"),
		toPtr("34.0.0.0/8"),
	}
}
