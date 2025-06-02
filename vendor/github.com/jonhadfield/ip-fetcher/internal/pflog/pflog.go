package pflog

import (
	"os"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
)

const DefaultLogLevel = logrus.InfoLevel

func GetFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	complete := runtime.FuncForPC(pc).Name()
	split := strings.Split(complete, "/")

	return split[len(split)-1]
}

func SetLogLevel() {
	// if set, then don't attempt to override with env var
	if logrus.GetLevel() != logrus.InfoLevel {
		return
	}

	envLvlRaw, ok := os.LookupEnv("PREFIX_FETCHER_LOG")
	if ok {
		envLvl, err := logrus.ParseLevel(envLvlRaw)
		if err != nil {
			logrus.Errorf("failed to parse env var PREFIX_FETCHER_LOG '%s'\n", envLvlRaw)

			return
		}
		logrus.SetLevel(envLvl)

		return
	}

	logrus.SetLevel(DefaultLogLevel)
}
