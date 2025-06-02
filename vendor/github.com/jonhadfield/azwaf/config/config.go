package config

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// ParseResourceID accepts an azure resource ID as a string and returns a struct instance containing the components.
func ParseResourceID(rawID string) ResourceID {
	components := strings.Split(rawID, "/")
	if len(components) != 9 {
		return ResourceID{}
	}

	return ResourceID{
		SubscriptionID: components[2],
		ResourceGroup:  components[4],
		Provider:       components[6],
		Name:           components[8],
		Raw:            rawID,
	}
}

func LoadFileConfig(path string) (config FileConfig, err error) {
	if path == "" {
		return config, nil
	}

	b, err := ReadFileBytes(path)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(b, &config)

	return config, err
}

type ResourceID struct {
	SubscriptionID string
	ResourceGroup  string
	Provider       string
	Name           string
	Raw            string
}

func NewResourceID(subID, rg, provider, name string) ResourceID {
	return ResourceID{
		SubscriptionID: subID,
		ResourceGroup:  rg,
		Provider:       provider,
		Name:           name,
		Raw: fmt.Sprintf(
			"/subscriptions/%s/resourceGroups/%s/providers/%s/%s",
			subID, rg, provider, name,
		),
	}
}

func (rid *ResourceID) SetSubscriptionID(subID string) {
	rid.SubscriptionID = subID
}

type FileConfig struct {
	PolicyAliases map[string]string `yaml:"policy_aliases"`
}

func GetFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	complete := runtime.FuncForPC(pc).Name()
	split := strings.Split(complete, "/")

	return split[len(split)-1]
}

func ReadFileBytes(path string) (content []byte, err error) {
	funcName := GetFunctionName()

	logrus.Debugf("%s | reading %s", funcName, path)

	if _, err = os.Stat(path); err != nil {
		err = fmt.Errorf("%s - %w", funcName, err)

		return
	}

	// #nosec
	content, err = os.ReadFile(path)
	if err != nil {
		err = fmt.Errorf("%s - %w", funcName, err)

		return
	}

	return
}
