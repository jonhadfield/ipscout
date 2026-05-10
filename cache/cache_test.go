package cache

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testKey         = "test-key"
	testKey2        = "test-key2"
	testItemVersion = "Item Version x1.2.3"
	testAppVersion  = "App Version x1.2.3"
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
	t.Cleanup(func() { require.NoError(t, d.Close()) })

	now := time.Now()
	require.NoError(t, UpsertWithTTL(l, d, Item{
		Key:        testKey,
		Value:      []byte("test value"),
		Version:    testItemVersion,
		AppVersion: testAppVersion,
		Created:    now,
	}, 1*time.Second))

	item, err := Read(l, d, testKey)
	require.NoError(t, err)
	require.Equal(t, testKey, item.Key)
	require.Equal(t, "test value", string(item.Value))
	require.Equal(t, testItemVersion, item.Version)
	require.Equal(t, testAppVersion, item.AppVersion)
	require.True(t, item.Created.Equal(now))

	time.Sleep(2 * time.Second)

	exists, err := CheckExists(l, d, testKey)
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
	t.Cleanup(func() { require.NoError(t, d.Close()) })

	now := time.Now()
	require.NoError(t, UpsertWithTTL(l, d, Item{
		Key:        testKey,
		Value:      []byte("test value"),
		Version:    testItemVersion,
		AppVersion: testAppVersion,
		Created:    now,
	}, 10*time.Second))

	exists, err := CheckExists(l, d, testKey)
	require.NoError(t, err)
	require.True(t, exists)
}

func TestDeleteOne(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	l := slog.New(slog.NewTextHandler(os.Stdout, nil))

	d, err := Create(l, tempDir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, d.Close()) })

	now := time.Now()
	require.NoError(t, UpsertWithTTL(l, d, Item{
		Key:        testKey,
		Value:      []byte("test value"),
		Version:    testItemVersion,
		AppVersion: testAppVersion,
		Created:    now,
	}, 10*time.Second))

	require.NoError(t, UpsertWithTTL(l, d, Item{
		Key:        testKey2,
		Value:      []byte("test value2"),
		Version:    testItemVersion,
		AppVersion: testAppVersion,
		Created:    now,
	}, 10*time.Second))

	require.NoError(t, Delete(l, d, testKey))
	exists, err := CheckExists(l, d, testKey)
	require.NoError(t, err)
	require.False(t, exists)
	exists, err = CheckExists(l, d, testKey2)
	require.NoError(t, err)
	require.True(t, exists)
}

func TestDeleteMultiple(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	l := slog.New(slog.NewTextHandler(os.Stdout, nil))

	d, err := Create(l, tempDir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, d.Close()) })

	now := time.Now()
	require.NoError(t, UpsertWithTTL(l, d, Item{
		Key:        testKey,
		Value:      []byte("test value"),
		Version:    testItemVersion,
		AppVersion: testAppVersion,
		Created:    now,
	}, 10*time.Second))

	require.NoError(t, UpsertWithTTL(l, d, Item{
		Key:        testKey2,
		Value:      []byte("test value2"),
		Version:    testItemVersion,
		AppVersion: testAppVersion,
		Created:    now,
	}, 10*time.Second))

	require.NoError(t, DeleteMultiple(l, d, []string{testKey, testKey2, "missing-key"}))
	exists, err := CheckExists(l, d, testKey)
	require.NoError(t, err)
	require.False(t, exists)
	exists, err = CheckExists(l, d, testKey2)
	require.NoError(t, err)
	require.False(t, exists)
}
