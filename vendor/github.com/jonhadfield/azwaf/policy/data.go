package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/jonhadfield/azwaf/config"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
)

// GetFrontDoorByID returns a front door instance for the provided id.
// It includes endpoints with any associated waf Policies.
func GetFrontDoorByID(s *session.Session, frontDoorID string) (FrontDoor, error) {
	funcName := GetFunctionName()
	ctx := context.Background()

	rID := config.ParseResourceID(frontDoorID)

	c, err := s.GetFrontDoorsClient(rID.SubscriptionID)
	if err != nil {
		return FrontDoor{}, fmt.Errorf("%s - %w", funcName, err)
	}

	rawFrontDoor, merr := c.Get(ctx, rID.ResourceGroup, rID.Name, nil)
	if merr != nil {
		return FrontDoor{}, fmt.Errorf("%s - %s", funcName, merr.Error())
	}

	policies := make(map[string]armfrontdoor.WebApplicationFirewallPolicy)

	var frontDoorEndpoints []FrontDoorEndpoint

	for _, e := range rawFrontDoor.Properties.FrontendEndpoints {
		if e.Properties.WebApplicationFirewallPolicyLink != nil && e.Properties.WebApplicationFirewallPolicyLink.ID != nil {
			var wafPolicy *armfrontdoor.WebApplicationFirewallPolicy

			val, ok := policies[*e.Properties.WebApplicationFirewallPolicyLink.ID]

			if !ok {
				rid := config.ParseResourceID(*e.Properties.WebApplicationFirewallPolicyLink.ID)

				wafPolicy, err = GetRawPolicy(s, rID.SubscriptionID, rid.ResourceGroup, rid.Name)
				if err != nil {
					return FrontDoor{}, fmt.Errorf("%s - %w", funcName, err)
				}

				policies[*e.Properties.WebApplicationFirewallPolicyLink.ID] = *wafPolicy
			} else {
				wafPolicy = &val
			}

			frontDoorEndpoints = append(frontDoorEndpoints, FrontDoorEndpoint{
				name:      *e.Name,
				hostName:  *e.Properties.HostName,
				wafPolicy: *wafPolicy,
			})
		}
	}

	return FrontDoor{
		name:      *rawFrontDoor.Name,
		endpoints: frontDoorEndpoints,
	}, nil
}

// PushPolicyInput defines the input for the pushPolicy function
type PushPolicyInput struct {
	Name          string
	Subscription  string
	ResourceGroup string
	Policy        armfrontdoor.WebApplicationFirewallPolicy
	Debug         bool
	Timeout       int64
	Async         bool
}

const (
	PushPolicyTimeout       = 120
	PushPolicyPollFrequency = 20
)

// PushPolicy creates or updates a waf Policy with the provided Policy instance.
func PushPolicy(s *session.Session, i *PushPolicyInput) error {
	funcName := GetFunctionName()

	logrus.Debugf("pushing policy %s...", *i.Policy.Name)

	ctx := context.Background()

	// check we're not missing a policies client for the Subscription
	err := s.GetFrontDoorPoliciesClient(i.Subscription)
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	poller, err := s.FrontDoorPoliciesClients[i.Subscription].BeginCreateOrUpdate(ctx, i.ResourceGroup, i.Name, i.Policy, nil)
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	if i.Async {
		logrus.Info("asynchronous policy push started")

		return nil
	}

	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)

		return err
	}

	logrus.Infof("policy %s updated", *i.Policy.Name)

	return nil
}

type GetWrappedPoliciesInput struct {
	SubscriptionID    string
	AppVersion        string
	Config            string
	FilterResourceIDs []string
	Max               int
}

type GetWrappedPoliciesOutput struct {
	Policies []WrappedPolicy
}

type FrontDoorEndpoint struct {
	name      string
	hostName  string
	wafPolicy armfrontdoor.WebApplicationFirewallPolicy
}

type FrontDoor struct {
	name      string
	endpoints []FrontDoorEndpoint
}

type FrontDoors []FrontDoor

func LoadPolicyFromFile(f string) (armfrontdoor.WebApplicationFirewallPolicy, error) {
	funcName := GetFunctionName()

	// #nosec
	data, err := os.ReadFile(f)
	if err != nil {
		return armfrontdoor.WebApplicationFirewallPolicy{},
			fmt.Errorf("%s - failed to read file %s: %w", funcName, f, err)
	}

	var p armfrontdoor.WebApplicationFirewallPolicy
	if err = json.Unmarshal(data, &p); err != nil {
		return armfrontdoor.WebApplicationFirewallPolicy{},
			fmt.Errorf("%s - failed to unmarshal policy: %w", funcName, err)
	}

	return p, nil
}

func LoadWrappedPolicyFromFile(f string) (WrappedPolicy, error) {
	funcName := GetFunctionName()
	logrus.Debugf("%s | loading file %s", funcName, f)
	// #nosec
	data, err := os.ReadFile(f)
	if err != nil {
		return WrappedPolicy{}, fmt.Errorf("%s - %w", funcName, err)
	}

	logrus.Debugf("%s | loaded %d bytes of data from %s", funcName, len(data), f)

	var wp WrappedPolicy

	err = json.Unmarshal(data, &wp)
	if err != nil {
		return WrappedPolicy{}, fmt.Errorf("%s - %w", funcName, err)
	}

	if wp.Policy.Properties == nil {
		return WrappedPolicy{}, fmt.Errorf("%s - wrapped policy is invalid", funcName)
	}

	return wp, nil
}

type Action struct {
	ActionType string `yaml:"action"`
	Policy     string
	Paths      []string `yaml:"paths"`
	MaxRules   int      `yaml:"max-rules"`
	Nets       IPNets
}

func LoadBackupsFromPaths(paths []string) ([]WrappedPolicy, error) {
	funcName := GetFunctionName()

	if len(paths) == 0 {
		return nil, fmt.Errorf("%s - no paths provided", funcName)
	}

	var all []WrappedPolicy

	for _, p := range paths {
		wps, err := LoadBackupsFromPath(p)
		if err != nil {
			return nil, fmt.Errorf("%s - %w", funcName, err)
		}

		all = append(all, wps...)
	}

	logrus.Debugf("loaded %d Policy backups", len(all))

	return all, nil
}

func LoadBackupsFromPath(rootPath string) ([]WrappedPolicy, error) {
	funcName := GetFunctionName()

	info, err := os.Stat(rootPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s - %w", funcName, err)
		}

		return nil, fmt.Errorf("%s - %w", funcName, err)
	}

	if !info.IsDir() {
		if !strings.EqualFold(filepath.Ext(info.Name()), ".json") {
			return nil, fmt.Errorf("%s - %s is not a json file", funcName, rootPath)
		}

		wp, err := LoadWrappedPolicyFromFile(rootPath)
		if err != nil {
			return nil, fmt.Errorf("%s - %w", funcName, err)
		}

		return []WrappedPolicy{wp}, nil
	}

	files, err := os.ReadDir(rootPath)
	if err != nil {
		return nil, fmt.Errorf("%s - %w", funcName, err)
	}

	var wps []WrappedPolicy

	for _, file := range files {
		if file.IsDir() || !strings.EqualFold(filepath.Ext(file.Name()), ".json") {
			continue
		}

		wp, err := LoadWrappedPolicyFromFile(filepath.Join(rootPath, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s - %w", funcName, err)
		}

		wps = append(wps, wp)
	}

	logrus.Debugf("loaded %d Policy backups", len(wps))

	return wps, nil
}
