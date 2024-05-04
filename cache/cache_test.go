package cache

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCreate(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	c, err := Create(slog.New(slog.NewTextHandler(os.Stdout, nil)), tempDir)
	require.NotNil(t, c)
	require.NoError(t, err)
	require.NoError(t, c.Close())
}

func TestCreateMissingPath(t *testing.T) {
	t.Parallel()

	c, err := Create(slog.New(slog.NewTextHandler(os.Stdout, nil)), "")
	require.Nil(t, c)
	require.Error(t, err)
}

func TestUpsert(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	l := slog.New(slog.NewTextHandler(os.Stdout, nil))

	d, err := Create(l, tempDir)
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, UpsertWithTTL(l, d, Item{
		Key:        "test-key",
		Value:      []byte("test value"),
		Version:    "Item Version x1.2.3",
		AppVersion: "App Version x1.2.3",
		Created:    now,
	}, 1*time.Second))

	item, err := Read(l, d, "test-key")
	require.NoError(t, err)
	require.Equal(t, "test-key", item.Key)
	require.Equal(t, "test value", string(item.Value))
	require.Equal(t, "Item Version x1.2.3", item.Version)
	require.Equal(t, "App Version x1.2.3", item.AppVersion)
	require.True(t, item.Created.Equal(now))

	time.Sleep(2 * time.Second)

	exists, err := CheckExists(l, d, "test-key")
	require.NoError(t, err)
	// check it's expired
	require.False(t, exists)
}

func TestCheckExists(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	l := slog.New(slog.NewTextHandler(os.Stdout, nil))

	d, err := Create(l, tempDir)
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, UpsertWithTTL(l, d, Item{
		Key:        "test-key",
		Value:      []byte("test value"),
		Version:    "Item Version x1.2.3",
		AppVersion: "App Version x1.2.3",
		Created:    now,
	}, 10*time.Second))

	exists, err := CheckExists(l, d, "test-key")
	require.NoError(t, err)
	require.True(t, exists)
}

func TestDeleteOne(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	l := slog.New(slog.NewTextHandler(os.Stdout, nil))

	d, err := Create(l, tempDir)
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, UpsertWithTTL(l, d, Item{
		Key:        "test-key",
		Value:      []byte("test value"),
		Version:    "Item Version x1.2.3",
		AppVersion: "App Version x1.2.3",
		Created:    now,
	}, 10*time.Second))

	require.NoError(t, UpsertWithTTL(l, d, Item{
		Key:        "test-key2",
		Value:      []byte("test value2"),
		Version:    "Item Version x1.2.3",
		AppVersion: "App Version x1.2.3",
		Created:    now,
	}, 10*time.Second))

	require.NoError(t, Delete(l, d, "test-key"))
	exists, err := CheckExists(l, d, "test-key")
	require.NoError(t, err)
	require.False(t, exists)
	exists, err = CheckExists(l, d, "test-key2")
	require.NoError(t, err)
	require.True(t, exists)
}

func TestDeleteMultiple(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	l := slog.New(slog.NewTextHandler(os.Stdout, nil))

	d, err := Create(l, tempDir)
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, UpsertWithTTL(l, d, Item{
		Key:        "test-key",
		Value:      []byte("test value"),
		Version:    "Item Version x1.2.3",
		AppVersion: "App Version x1.2.3",
		Created:    now,
	}, 10*time.Second))

	require.NoError(t, UpsertWithTTL(l, d, Item{
		Key:        "test-key2",
		Value:      []byte("test value2"),
		Version:    "Item Version x1.2.3",
		AppVersion: "App Version x1.2.3",
		Created:    now,
	}, 10*time.Second))

	require.NoError(t, DeleteMultiple(l, d, []string{"test-key", "test-key2", "missing-key"}))
	exists, err := CheckExists(l, d, "test-key")
	require.NoError(t, err)
	require.False(t, exists)
	exists, err = CheckExists(l, d, "test-key2")
	require.NoError(t, err)
	require.False(t, exists)
}
