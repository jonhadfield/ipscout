package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/mitchellh/go-homedir"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	conf := New()
	require.NotNil(t, conf)
	require.NotNil(t, conf.Stats)
	require.NotNil(t, conf.Stats.InitialiseDuration)
	require.NotNil(t, conf.Stats.InitialiseUsedCache)
	require.NotNil(t, conf.Stats.FindHostDuration)
	require.NotNil(t, conf.Stats.FindHostUsedCache)
	require.NotNil(t, conf.Stats.CreateTableDuration)
}

func TestUnmarshalConfig(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		data := []byte(DefaultConfig)
		conf, err := unmarshalConfig(data)
		require.NoError(t, err)
		require.NotNil(t, conf)
	})

	t.Run("InvalidConfig", func(t *testing.T) {
		data := []byte("invalid session")
		conf, err := unmarshalConfig(data)
		require.Error(t, err)
		require.Nil(t, conf)
	})
}

func TestCreateDefaultConfig(t *testing.T) {
	t.Run("PathExists", func(t *testing.T) {
		path := t.TempDir()
		created, err := CreateDefaultConfigIfMissing(path)
		require.NoError(t, err)
		require.True(t, created)
	})

	t.Run("PathDoesNotExist", func(t *testing.T) {
		path := t.TempDir()
		created, err := CreateDefaultConfigIfMissing(path)
		require.NoError(t, err)
		require.True(t, created)

		_, err = os.Stat(path)
		require.NoError(t, err)
	})

	t.Run("InvalidPath", func(t *testing.T) {
		path := ""
		created, err := CreateDefaultConfigIfMissing(path)
		require.Error(t, err)
		require.False(t, created)
	})
}

func TestCreateCachePathIfNotExist(t *testing.T) {
	t.Run("PathExists", func(t *testing.T) {
		tempDir := t.TempDir()

		configRoot := GetConfigRoot(tempDir, "", constants.AppName)

		// create session root (required for cache path)
		created, err := CreateDefaultConfigIfMissing(configRoot)
		require.NoError(t, err)
		require.True(t, created)

		// check session root exists
		_, err = os.Stat(configRoot)
		require.NoError(t, err)

		// check cache path does not exist
		_, err = os.Stat(filepath.Join(configRoot, "cache"))
		require.ErrorIs(t, err, os.ErrNotExist)

		// create cache path
		require.NoError(t, CreateConfigPathStructure(configRoot))
		// check cache path exists
		for _, dir := range []string{"cache"} {
			_, err = os.Stat(filepath.Join(configRoot, dir))
			require.NoError(t, err)
		}
	})

	t.Run("PathDoesNotExist", func(t *testing.T) {
		tempDir := t.TempDir()
		configRoot := GetConfigRoot(tempDir, "", constants.AppName)

		// create session root (required for cache path)
		created, err := CreateDefaultConfigIfMissing(configRoot)
		require.NoError(t, err)
		require.True(t, created)

		err = CreateConfigPathStructure(configRoot)
		require.NoError(t, err)

		for _, dir := range []string{"cache"} {
			_, err = os.Stat(filepath.Join(configRoot, dir))
			require.NoError(t, err)
		}
	})

	t.Run("InvalidPath", func(t *testing.T) {
		path := ""
		err := CreateConfigPathStructure(path)
		require.Error(t, err)
	})
}

func TestGetConfigRoot(t *testing.T) {
	t.Run("ValidAppName", func(t *testing.T) {
		dir := t.TempDir()
		appName := "test"
		path := GetConfigRoot(dir, "", appName)
		require.Equal(t, filepath.Join(dir, ".config", appName), path)
	})

	t.Run("EmptyAppName", func(t *testing.T) {
		appName := ""
		dir, err := homedir.Dir()
		require.NoError(t, err)

		path := GetConfigRoot("", dir, appName)
		require.Equal(t, filepath.Join(dir, ".config", appName), path)
	})
}
