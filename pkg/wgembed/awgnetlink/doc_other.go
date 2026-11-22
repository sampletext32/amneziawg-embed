//go:build !linux

// Package awgnetlink is the generic-netlink client for the AmneziaWG kernel
// module. It only exists on Linux; this file keeps the package buildable
// (empty) everywhere else so that a cross-platform `go build ./...` succeeds.
package awgnetlink
