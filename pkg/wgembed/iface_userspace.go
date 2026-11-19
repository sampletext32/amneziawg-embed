//go:build !windows
// +build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

// modified from https://git.zx2c4.com/wireguard-go, with the device taken from
// the AmneziaWG fork of that implementation.

package wgembed

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// uapiSocketDirectory is where wgctrl looks for a userspace device's UAPI
// socket. AmneziaWG's own ipc package listens in /var/run/amneziawg, which
// wgctrl never scans - so this implementation creates the listener here
// instead and hands the connections to the device itself. That keeps the
// wgctrl-based configuration (and everything built on it, including the kernel
// route synchronisation) working unchanged.
const uapiSocketDirectory = "/var/run/wireguard"

// userspaceInterface represents an userspace wireguard-go
// network interface
type userspaceInterface struct {
	commonInterface
	device *device.Device
	uapi   net.Listener
}

func newUserspaceInterface(opts Options) (WireGuardInterface, error) {
	wg := &userspaceInterface{
		commonInterface: commonInterface{
			name:         opts.InterfaceName,
			manageRoutes: opts.ManageRoutes,
		},
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create wg client: %w", err)
	}

	tunDevice, err := tun.CreateTUN(wg.name, device.DefaultMTU)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	uapi, err := listenUAPI(wg.name)
	if err != nil {
		_ = tunDevice.Close()
		_ = client.Close()
		return nil, fmt.Errorf("UAPI listen error: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", wg.name))
	// from here on the device owns tunDevice and closes it
	wg.device = device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	// The AmneziaWG parameters are the one thing a UAPI client cannot set
	// through wgctrl: they have no wgtypes.Config field. This implementation
	// holds the device, so it sends them to it directly, over the same UAPI
	// protocol, without touching what is already configured.
	wg.applyAmnezia = func(a AmneziaConfig) error {
		body, err := a.uapi()
		if err != nil {
			return err
		}
		if body == "" {
			return nil
		}
		return wg.device.IpcSet(body)
	}

	wg.client = client
	wg.uapi = uapi

	go func() {
		for {
			connection, err := uapi.Accept()
			if err != nil {
				// the listener was closed; nothing is left to serve
				return
			}
			go wg.device.IpcHandle(connection)
		}
	}()

	return wg, nil
}

// listenUAPI creates the UAPI socket where wgctrl looks for it. A leftover from
// a run that was killed is replaced: the interface it belonged to is gone, and
// the constructor has already refused a name that is still taken.
func listenUAPI(name string) (net.Listener, error) {
	if err := os.MkdirAll(uapiSocketDirectory, 0o755); err != nil {
		return nil, err
	}

	socketPath := filepath.Join(uapiSocketDirectory, name+".sock")
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("removing a stale UAPI socket: %w", err)
	}

	address, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, err
	}

	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return nil, err
	}
	// The private key travels over this socket, so keep it to this user - the
	// same mode wireguard-go's own UAPI socket has.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	// Closing the interface removes the socket; nothing is left to dial.
	listener.SetUnlinkOnClose(true)

	return listener, nil
}

// Wait will return a channel that signals when the
// wireguard interface is stopped
func (wg *userspaceInterface) Wait() chan struct{} {
	return wg.device.Wait()
}

// Close will stop and clean up both the wireguard
// interface and userspace configuration api. It always releases everything,
// even when one step fails, and calling it again is a no-op.
func (wg *userspaceInterface) Close() error {
	wg.closeOnce.Do(func() {
		wg.closeErr = wg.uapi.Close()
		wg.device.Close()
		if err := wg.client.Close(); err != nil && wg.closeErr == nil {
			wg.closeErr = err
		}
	})
	return wg.closeErr
}
