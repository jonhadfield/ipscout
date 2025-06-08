package policy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/ztrue/tracerr"
)

func toJSON(i interface{}) (out string, err error) {
	switch v := i.(type) {
	case string:
		// v already contains the json string
		return v, nil
	case []byte:
		// return the byte slice as a string without attempting to unmarshal
		return string(v), nil
	case armfrontdoor.WebApplicationFirewallPolicy:
		var j []byte

		j, err = json.MarshalIndent(v, "", "  ")
		if err != nil {
			return "", tracerr.Wrap(err)
		}

		return string(j), nil
	case WrappedPolicy:
		var j []byte

		j, err = json.MarshalIndent(v.Policy, "", "  ")
		if err != nil {
			return "", tracerr.Wrap(err)
		}

		return string(j), nil
	default:
		return "", tracerr.Errorf("unexpected type: %s", reflect.TypeOf(i).String())
	}
}

func actionStringToActionType(action string) (at armfrontdoor.ActionType, err error) {
	switch strings.ToLower(action) {
	case "block":
		return armfrontdoor.ActionTypeBlock, nil
	case "allow":
		return armfrontdoor.ActionTypeAllow, nil
	case "log":
		return armfrontdoor.ActionTypeLog, nil
	default:
		return at, fmt.Errorf("unexpected action: %s", action)
	}
}

func deRefStrs(strPs []*string) (strs []string) {
	for x := range strPs {
		strs = append(strs, *strPs[x])
	}

	return
}

func Int32ToPointer(i int32) (p *int32) {
	return &i
}

func splitRuleSetName(rsName string) (rsType, rsVersion string, err error) {
	funcName := GetFunctionName()
	if rsName == "" {
		err = fmt.Errorf("%s - rule set name missing", funcName)

		return
	}

	pos := strings.LastIndex(rsName, "_")
	if pos == -1 {
		err = fmt.Errorf("rule set name %s missing underscore character", rsName)

		return
	}

	return rsName[:pos], rsName[pos+1:], nil
}

func GetFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	complete := runtime.FuncForPC(pc).Name()
	split := strings.Split(complete, "/")

	return split[len(split)-1]
}

func toPtr[T any](v T) *T {
	return &v
}

func IsIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}
