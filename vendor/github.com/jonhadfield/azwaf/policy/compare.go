package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/google/uuid"
	"github.com/jonhadfield/findexec"
	"github.com/sirupsen/logrus"
)

func compare(original interface{}, updated []byte) (differencesFound bool, err error) {
	funcName := GetFunctionName()

	logrus.Debugf("%s | finding differences between the current policy version and the proposed", funcName)

	var originalBytes []byte

	switch v := original.(type) {
	case *armfrontdoor.WebApplicationFirewallPolicy:
		originalBytes, err = json.MarshalIndent(v, "", "  ")
		if err != nil {
			return
		}
	case []byte:
		break
	default:
		return false, errors.New("unexpected type")
	}

	diffBinary := findexec.Find("diff", "")
	if diffBinary == "" {
		err = errors.New("failed to find compare binary")

		return
	}

	// getTagsWithNotes tempdir
	tempDir := os.TempDir()
	if !strings.HasSuffix(tempDir, string(os.PathSeparator)) {
		tempDir += string(os.PathSeparator)
	}

	originalJSONB, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		return
	}

	newJSONB, err := json.MarshalIndent(updated, "", "  ")
	if err != nil {
		return
	}

	originalJSON := string(originalJSONB)
	newJSON := string(newJSONB)

	if originalJSON == newJSON {
		return false, nil
	}

	differencesFound = true

	// write local and remote content to temporary files
	var f1, f2 *os.File

	uid := uuid.New().String()
	f1path := filepath.Join(tempDir, fmt.Sprintf("waf-afd-policy-%s-f1", uid))
	f1path = filepath.Clean(f1path)

	f2path := filepath.Join(tempDir, fmt.Sprintf("waf-afd-policy-%s-f2", uid))
	f2path = filepath.Clean(f2path)

	// #nosec
	f1, err = os.Create(f1path)
	if err != nil {
		return
	}
	// #nosec
	f2, err = os.Create(f2path)
	if err != nil {
		return
	}

	if _, err = f1.Write(originalBytes); err != nil {
		return
	}

	if _, err = f2.WriteString(newJSON); err != nil {
		return
	}

	// #nosec
	cmd := exec.Command(diffBinary, "-u", f1path, f2path)

	_, oErr := cmd.CombinedOutput()

	if err = os.Remove(f1path); err != nil {
		return
	}

	if err = os.Remove(f2path); err != nil {
		return
	}

	var exitCode int

	if oErr != nil {
		if exitError, ok := oErr.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		}
	}

	if exitCode == 2 {
		panic(fmt.Sprintf("failed to compare: '%s' with '%s'", f1path, f2path))
	}

	return differencesFound, err
}
