package process

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("New", func(t *testing.T) {
		n, err := New(session.New())
		require.NoError(t, err)
		require.NotNil(t, n)
	})
}
