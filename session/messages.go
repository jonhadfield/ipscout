package session

import "errors"

var (
	ErrLoggerNotSet = errors.New("logger not set")
	ErrStatsNotSet  = errors.New("stats not set")
	ErrCacheNotSet  = errors.New("cache not set")
)
