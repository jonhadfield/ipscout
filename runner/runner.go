// Package runner holds shared provider orchestration used by process and rate.
package runner

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/jedib0t/go-pretty/v6/text"
	c "github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/registry"
	"github.com/jonhadfield/ipscout/session"
	"golang.org/x/sync/errgroup"
)

const spinnerIntervalMS = 100

// ClientOptions controls which enabled providers are instantiated.
type ClientOptions struct {
	// RatingOnly keeps providers that support host rating.
	RatingOnly bool
	// RequireEnabled returns an error when no provider is marked enabled in config.
	RequireEnabled bool
}

// GetEnabledProviderClients builds clients for every enabled registry entry
// matching opts.
func GetEnabledProviderClients(sess session.Session, opts ClientOptions) (map[string]providers.ProviderClient, error) {
	runners := make(map[string]providers.ProviderClient)

	var enabled int

	for _, entry := range registry.All() {
		if opts.RatingOnly && !entry.SupportsRating {
			continue
		}

		entryEnabled := entry.Enabled(sess)
		if entryEnabled == nil || !*entryEnabled {
			continue
		}

		enabled++

		client, err := entry.NewClient(sess)
		if err != nil {
			return nil, fmt.Errorf("error creating %s client: %w", entry.Name, err)
		}

		if client != nil && (client.Enabled() || sess.UseTestData) {
			runners[entry.Name] = client
		}
	}

	if opts.RequireEnabled && enabled == 0 {
		return nil, errors.New("no providers enabled")
	}

	return runners, nil
}

// GetEnabledProviders filters clients to those whose Enabled() is true.
func GetEnabledProviders(runners map[string]providers.ProviderClient) map[string]providers.ProviderClient {
	res := make(map[string]providers.ProviderClient)

	for k, r := range runners {
		if r.Enabled() {
			res[k] = r
		}
	}

	if len(res) == 0 {
		return nil
	}

	return res
}

// InitialiseProviders runs Initialise concurrently for every enabled runner.
func InitialiseProviders(sess *session.Session, runners map[string]providers.ProviderClient, hideProgress bool) {
	var g errgroup.Group

	// failures are collected rather than logged as they happen, so a slow
	// download is not interrupted by output, and reported as one line after
	// the results
	var (
		failedMu sync.Mutex
		failed   []string
	)

	s := spinner.New(spinner.CharSets[11], spinnerIntervalMS*time.Millisecond, spinner.WithWriter(os.Stderr))

	if !hideProgress {
		s.Start()
		s.Suffix = " initialising providers..."

		defer stopSpinnerIfActive(s)
	}

	for name, runner := range runners {
		if !runner.Enabled() {
			continue
		}

		g.Go(func() error {
			gErr := runner.Initialise()
			if gErr != nil {
				sess.Logger.Debug("failed to initialise", "provider", name, "error", gErr.Error())

				// a provider that has already said what went wrong, and what to do
				// about it, is left out of the generic line rather than named twice
				if errors.Is(gErr, providers.ErrFailureReported) {
					return nil
				}

				failedMu.Lock()

				failed = append(failed, name)
				failedMu.Unlock()
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		stopSpinnerIfActive(s)

		return
	}

	reportFailedProviders(sess, failed)
}

func reportFailedProviders(sess *session.Session, failed []string) {
	if len(failed) == 0 {
		return
	}

	sort.Strings(failed)

	sess.Messages.AddError(fmt.Sprintf(c.MsgFetchFailedFmt, strings.Join(failed, ", ")))
}

func stopSpinnerIfActive(s *spinner.Spinner) {
	if s != nil && s.Active() {
		s.Stop()
	}
}

// HostResults holds per-provider FindHost payloads.
type HostResults struct {
	sync.RWMutex
	Data map[string][]byte
}

// FindHosts queries every runner for the session host concurrently.
func FindHosts(runners map[string]providers.ProviderClient, hideProgress bool) *HostResults {
	results := &HostResults{}

	results.Lock()
	results.Data = make(map[string][]byte)
	results.Unlock()

	var w sync.WaitGroup

	if !hideProgress {
		s := spinner.New(spinner.CharSets[11], spinnerIntervalMS*time.Millisecond, spinner.WithWriter(os.Stderr))
		s.Start()
		s.Suffix = " searching providers..."

		defer s.Stop()
	}

	for name, runner := range runners {
		w.Add(1)

		go func() {
			defer w.Done()

			result, err := runner.FindHost()
			if err != nil {
				// a host not appearing in a provider's data is routine
				if errors.Is(err, providers.ErrNoMatchFound) {
					runner.GetConfig().Logger.Debug(err.Error())
				} else {
					runner.GetConfig().Logger.Info(err.Error())
				}

				return
			}

			if result != nil {
				results.Lock()
				results.Data[name] = result
				results.Unlock()
			}
		}()
	}

	w.Wait()

	return results
}

// OutputMessages prints buffered session messages below results.
func OutputMessages(sess *session.Session) {
	for _, msg := range sess.Messages.Error {
		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", text.FgRed.Sprint("[ERROR]"), msg)
	}

	for _, msg := range sess.Messages.Warning {
		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", text.FgYellow.Sprint("[WARN]"), msg)
	}

	for _, msg := range sess.Messages.Info {
		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", text.FgGreen.Sprint("[INFO]"), msg)
	}
}

// MapsKeys returns the keys of m.
func MapsKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))

	for key := range m {
		keys = append(keys, key)
	}

	return keys
}
