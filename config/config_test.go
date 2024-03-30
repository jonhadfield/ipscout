package config

import (
	"github.com/mitchellh/go-homedir"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalConfig(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		data := []byte(defaultConfig)
		conf, err := unmarshalConfig(data)
		assert.NoError(t, err)
		assert.NotNil(t, conf)
	})

	t.Run("InvalidConfig", func(t *testing.T) {
		data := []byte("invalid config")
		conf, err := unmarshalConfig(data)
		assert.Error(t, err)
		assert.Nil(t, conf)
	})
}

func TestCreateDefaultConfig(t *testing.T) {
	t.Run("PathExists", func(t *testing.T) {
		path := "/tmp"
		err := CreateDefaultConfigIfMissing(path)
		assert.NoError(t, err)
	})

	t.Run("PathDoesNotExist", func(t *testing.T) {
		path := "/tmp/nonexistent"
		err := CreateDefaultConfigIfMissing(path)
		assert.NoError(t, err)
		_, err = os.Stat(path)
		assert.NoError(t, err)
	})

	t.Run("InvalidPath", func(t *testing.T) {
		path := ""
		err := CreateDefaultConfigIfMissing(path)
		assert.Error(t, err)
	})
}

func TestCreateCachePathIfNotExist(t *testing.T) {

	t.Run("PathExists", func(t *testing.T) {
		dir := t.TempDir()

		configRoot := GetConfigRoot(dir, AppName)

		// create config root (required for cache path)
		require.NoError(t, CreateDefaultConfigIfMissing(configRoot))

		// check config root exists
		_, err := os.Stat(configRoot)
		require.NoError(t, err)

		// check cache path does not exist
		_, err = os.Stat(filepath.Join(configRoot, "cache"))
		require.ErrorIs(t, err, os.ErrNotExist)

		// create cache path
		require.NoError(t, CreateCachePathIfNotExist(configRoot))
		// check cache path exists
		_, err = os.Stat(filepath.Join(configRoot, "cache"))
		require.NoError(t, err)

		// create cache path for a second time (if not exists)
		require.NoError(t, CreateCachePathIfNotExist(configRoot))
		// check cache path exists
		_, err = os.Stat(filepath.Join(configRoot, "cache"))
		require.NoError(t, err)
	})

	t.Run("PathDoesNotExist", func(t *testing.T) {
		dir := t.TempDir()
		configRoot := GetConfigRoot(dir, AppName)

		// create config root (required for cache path)
		require.NoError(t, CreateDefaultConfigIfMissing(configRoot))

		err := CreateCachePathIfNotExist(configRoot)
		assert.NoError(t, err)
		_, err = os.Stat(filepath.Join(configRoot, "cache"))
		assert.NoError(t, err)
	})

	t.Run("InvalidPath", func(t *testing.T) {
		path := ""
		err := CreateCachePathIfNotExist(path)
		assert.Error(t, err)
	})
}

func TestGetConfigRoot(t *testing.T) {
	t.Run("ValidAppName", func(t *testing.T) {
		dir := t.TempDir()
		appName := "test"
		path := GetConfigRoot(dir, appName)
		require.Equal(t, filepath.Join(dir, ".config", appName), path)
	})

	t.Run("EmptyAppName", func(t *testing.T) {
		appName := ""
		dir, err := homedir.Dir()
		require.NoError(t, err)

		path := GetConfigRoot("", appName)
		require.Equal(t, filepath.Join(dir, ".config", appName), path)
	})
}
