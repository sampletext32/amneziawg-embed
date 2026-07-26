//go:build !linux

package wgembed

func NewWithOpts(Options) (WireGuardInterface, error) { return nil, ErrUnsupportedPlatform }
