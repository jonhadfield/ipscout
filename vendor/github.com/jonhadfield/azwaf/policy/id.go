package policy

import (
	"fmt"
	"regexp"

	"github.com/jonhadfield/azwaf/config"
)

func IsRIDHash(s string) bool {
	if len(s) != 8 {
		return false
	}

	hashExp := regexp.MustCompile(`[a-f\d]{8}`)

	return hashExp.MatchString(s)
}

// ConvertToResourceIDs accepts a slice of strings representing resource ids and/or hashes
// and returns a slice of matching resource ids
func ConvertToResourceIDs(ids []string, subID string) (rids []config.ResourceID, err error) {
	funcName := GetFunctionName()

	for _, id := range ids {
		if IsRIDHash(id) {
			id, err = GetPolicyRIDByHash(nil, subID, id)
			if err != nil {
				return nil, err
			}
		}

		rid := config.ParseResourceID(id)
		if rid.Name == "" {
			return nil, fmt.Errorf("%s - resource id '%s' is invalid", funcName, id)
		}

		rids = append(rids, rid)
	}

	return rids, nil
}
