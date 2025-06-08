package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/findexec"
	"github.com/sirupsen/logrus"
)

func compare(original interface{}, updated []byte) (differencesFound bool, err error) {
	funcName := GetFunctionName()

	logrus.Debugf("%s | finding differences between the current policy version and the proposed", funcName)

	diffBinary := findexec.Find("diff", "")
	if diffBinary == "" {
		return false, errors.New("failed to find compare binary")
	}

	origJSON, err := marshalJSON(original)
	if err != nil {
		return false, err
	}

	newJSON, err := marshalJSON(updated)
	if err != nil {
		return false, err
	}

	if bytes.Equal(origJSON, newJSON) {
		return false, nil
	}

	differencesFound = true

	f1, err := writeTempFile(origJSON)
	if err != nil {
		return false, err
	}
	defer os.Remove(f1)

	f2, err := writeTempFile(newJSON)
	if err != nil {
		return false, err
	}
	defer os.Remove(f2)

	exitCode, err := runDiff(diffBinary, f1, f2)
	if err != nil {
		return false, err
	}

	if exitCode == 2 {
		return false, fmt.Errorf("failed to compare: '%s' with '%s'", f1, f2)
	}

	return differencesFound, nil
}

func marshalJSON(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case []byte:
		var out interface{}
		if err := json.Unmarshal(val, &out); err != nil {
			return nil, err
		}
		return json.MarshalIndent(out, "", "  ")
	case *armfrontdoor.WebApplicationFirewallPolicy:
		return json.MarshalIndent(val, "", "  ")
	default:
		return nil, errors.New("unexpected type")
	}
}

func writeTempFile(data []byte) (string, error) {
	f, err := os.CreateTemp("", "waf-afd-policy-")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func runDiff(binary, f1, f2 string) (int, error) {
	// #nosec
	cmd := exec.Command(binary, "-u", f1, f2)
	_, err := cmd.CombinedOutput()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode(), nil
		}
		return 0, err
	}
	return 0, nil
}
