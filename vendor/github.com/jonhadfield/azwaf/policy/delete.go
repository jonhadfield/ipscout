package policy

import (
	"fmt"
	"runtime"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/sirupsen/logrus"
)

func displayStringDiffWithLib(orig, latest string) {
	edits := myers.ComputeEdits("", orig, latest)
	fmt.Println(gotextdiff.ToUnified("", "", orig, edits))
}

func DisplayPolicyDiff(original, latest interface{}) error {
	funcName := GetFunctionName()

	var err error

	originalJSON, err := toJSON(original)
	if err != nil {
		return err
	}

	newJSON, err := toJSON(latest)
	if err != nil {
		return err
	}

	platform := runtime.GOOS
	logrus.Debugf("%s | detected %s", funcName, platform)

	switch platform {
	case "linux":
		err = DisplayStringDiffWithDiffTool(originalJSON, newJSON)
		if err != nil {
			displayStringDiffWithLib(originalJSON, newJSON)
		}
	case "darwin":
		displayStringDiffWithLib(originalJSON, newJSON)
	default:
		logrus.Warnf("untested on OS %s. let me know if this works", platform)
		displayStringDiffWithLib(originalJSON, newJSON)
	}

	return err
}
