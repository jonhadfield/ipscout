package providers

import (
	"errors"
)

var (
	ErrNoDataFound         = errors.New("no data found")
	ErrDataProviderFailure = errors.New("data provider failure")
)
