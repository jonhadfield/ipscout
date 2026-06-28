package rate

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
	"github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/require"
)

// fakeCompleter is an injectable ChatCompleter that returns a canned response,
// so aiRate can be exercised without calling OpenAI.
type fakeCompleter struct {
	resp openai.ChatCompletionResponse
	err  error
}

func (f fakeCompleter) CreateChatCompletion(_ context.Context, _ openai.ChatCompletionRequest) (openai.ChatCompletionResponse, error) {
	return f.resp, f.err
}

func newRaterWithCompleter(t *testing.T, c ChatCompleter) *Rater {
	t.Helper()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	return &Rater{
		Session:  &session.Session{Logger: lg, Stats: session.CreateStats()},
		AIClient: c,
	}
}

func emptyResults() *findHostsResults {
	return &findHostsResults{m: map[string][]byte{}}
}

func TestAIRateSuccess(t *testing.T) {
	t.Parallel()

	r := newRaterWithCompleter(t, fakeCompleter{
		resp: openai.ChatCompletionResponse{
			Choices: []openai.ChatCompletionChoice{
				{Message: openai.ChatCompletionMessage{Content: "recommend blocking"}},
			},
		},
	})

	require.NoError(t, aiRate(r, map[string]providers.ProviderClient{}, emptyResults()))
}

func TestAIRateNoChoices(t *testing.T) {
	t.Parallel()

	r := newRaterWithCompleter(t, fakeCompleter{resp: openai.ChatCompletionResponse{}})

	err := aiRate(r, map[string]providers.ProviderClient{}, emptyResults())
	require.ErrorContains(t, err, "no choices")
}

func TestAIRateCompletionError(t *testing.T) {
	t.Parallel()

	r := newRaterWithCompleter(t, fakeCompleter{err: errors.New("api down")})

	err := aiRate(r, map[string]providers.ProviderClient{}, emptyResults())
	require.ErrorContains(t, err, "api down")
}
