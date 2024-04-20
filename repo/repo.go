package annotated

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/go-git/go-git/v5"
	"github.com/jonhadfield/ipq/common"
	"github.com/jonhadfield/ipq/session"
	"github.com/sirupsen/logrus"
)

func generateRepoFilesystemPath(root, repoUrl string, excludeName bool) (path string, err error) {
	parsed, err := url.Parse(repoUrl)
	if err != nil {
		return
	}

	if excludeName {
		parts := strings.Split(parsed.Path, "/")
		parsed.Path = strings.Join(parts[:len(parts)-1], "/")
	}

	return filepath.Join(root, parsed.Host, parsed.Path), nil
}

// CloneLists will clone git repositories containing lists of IP addresses for trusted, untrusted, and attackers
func CloneLists(listsConfig session.AnnotatedConfig) error {
	funcName := common.GetFunctionName()

	start := time.Now()

	for _, repository := range listsConfig.Repositories {
		path, err := generateRepoFilesystemPath(listsConfig.Root, repository.Url, false)
		if err != nil {
			return err
		}

		logrus.Debugf("%s | cloning repo url %s to %s", funcName, repository.Url, path)

		var pathExists bool
		if _, pathErr := os.Stat(path); pathErr == nil {
			pathExists = true
		}

		// if path exists, then do a pull
		var pullErr error

		if pathExists {
			logrus.Infof("%s | attempt to update previously cloned repo %s", funcName, repository.Url)

			r, openErr := git.PlainOpen(path)
			if openErr != nil {
				logrus.Warnf("%s | failed to open repo path %s: %s", funcName, path, openErr.Error())
			} else {
				w, wErr := r.Worktree()
				if wErr == nil {
					startPull := time.Now()
					logrus.Infof("%s | pulling updates for %s", funcName, repository.Url)
					// logrus.Infof("%s | pulling updates for %s in %s", funcName, repository.Url, path)
					if pullErr = w.Pull(&git.PullOptions{
						Auth: &http.BasicAuth{
							Username: repository.GitHubUser,
							Password: repository.GitHubToken,
						},
						ReferenceName:     "",
						SingleBranch:      false,
						Depth:             0,
						RecurseSubmodules: 0,
						Progress:          nil,
						Force:             true,
						InsecureSkipTLS:   false,
					}); pullErr == nil || pullErr == git.NoErrAlreadyUpToDate {
						logrus.Infof("%s | pull of path %s completed successfully", funcName, path)
						logrus.Debugf("%s | pull of path %s completed successfully in %v", funcName, path, time.Since(startPull))

						continue
					}

					logrus.Warnf("%s | failed to pull %s in path %s: %s", funcName, repository.Url, path, pullErr.Error())
				} else {
					logrus.Errorf("%s | failed to get worktree for %s: %s", funcName, path, wErr.Error())
				}
			}
		}

		// path doesn't exist or pull failed so remove path
		err = os.RemoveAll(path)
		if err != nil {
			logrus.Errorf("failed to delete existing path %s: %s", path, err)

			continue
		}

		if _, err = os.Stat(path); os.IsNotExist(err) {
			logrus.Infof("%s | cloning %s to %s", funcName, repository.Url, path)

			startClone := time.Now()
			_, err = git.PlainClone(path, false, &git.CloneOptions{
				Auth: &http.BasicAuth{
					Username: repository.GitHubUser,
					Password: repository.GitHubToken,
				},
				URL:      repository.Url,
				Progress: os.Stdout,
			})

			logrus.Infof("%s | clone %s to %s took %v", funcName, repository.Url, path, time.Since(startClone))

			if err != nil {
				logrus.Errorf("%s | failed to clone repo %s - %s", funcName, repository.Url, err.Error())
				return err
			}

			return nil
		}
	}

	logrus.Debugf("CloneLists completed in %v", time.Since(start))

	return nil
}
