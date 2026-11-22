//go:build linux

package wgembed

import (
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/sampletext32/amneziawg-embed/pkg/wgembed/awgnetlink"
)

// kernelInterface is the AmneziaWG kernel module's own rtnl device ("type
// amneziawg"), configured through the module's generic-netlink family.
//
// It is a different device from the stock kernel WireGuard interface: the link
// type, the family and the attribute set all belong to the module, and the
// AmneziaWG parameters are extra device attributes that wgctrl does not know.
type kernelInterface struct {
	commonInterface
}

// newKernelInterface creates the link and the netlink client. Every failure
// removes the link again, so the caller can fall back to the userspace device
// without tripping over ErrInterfaceExists.
func newKernelInterface(opts Options) (WireGuardInterface, error) {
	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: opts.InterfaceName},
		LinkType:  "amneziawg",
	}
	if err := netlink.LinkAdd(link); err != nil {
		return nil, fmt.Errorf(
			"creating the amneziawg kernel device failed (is the amneziawg-dkms module installed and loaded on this node?): %w", err)
	}

	client, err := awgnetlink.New()
	if err != nil {
		_ = netlink.LinkDel(link)
		return nil, err
	}

	wg := &kernelInterface{
		commonInterface: commonInterface{
			name:         opts.InterfaceName,
			client:       client,
			manageRoutes: opts.ManageRoutes,
		},
	}
	// The one thing wgctrl (and therefore commonInterface.LoadConfig) cannot
	// send: the AmneziaWG parameters. They go to the same device as a second,
	// merging netlink message.
	wg.applyAmnezia = func(a AmneziaConfig) error {
		return client.SetAmnezia(wg.name, kernelAmneziaConfig(a))
	}

	logrus.Infof("dataplane: kernel (amneziawg kernel module, netlink family v%d, interface %s)",
		client.FamilyVersion(), opts.InterfaceName)
	return wg, nil
}

// kernelAmneziaConfig converts the package's configuration type into the netlink
// package's copy of it. The two packages cannot import each other (wgembed
// imports awgnetlink), and the fields are the same pointers, so this is a move.
func kernelAmneziaConfig(a AmneziaConfig) awgnetlink.AmneziaConfig {
	return awgnetlink.AmneziaConfig{
		JC:                     a.JC,
		JMin:                   a.JMin,
		JMax:                   a.JMax,
		S1:                     a.S1,
		S2:                     a.S2,
		S3:                     a.S3,
		S4:                     a.S4,
		H1:                     a.H1,
		H2:                     a.H2,
		H3:                     a.H3,
		H4:                     a.H4,
		I1:                     a.I1,
		I2:                     a.I2,
		I3:                     a.I3,
		I4:                     a.I4,
		I5:                     a.I5,
		HeaderProtectionKey:    a.HeaderProtectionKey,
		RandomTrailers:         a.RandomTrailers,
		DisableCookies:         a.DisableCookies,
		ContentPaddingAddition: a.ContentPaddingAddition,
		RekeyAfterTime:         a.RekeyAfterTime,
		RekeyTimeout:           a.RekeyTimeout,
		RejectAfterTime:        a.RejectAfterTime,
		KeepaliveTimeout:       a.KeepaliveTimeout,
		MaxHandshakeAttempts:   a.MaxHandshakeAttempts,
	}
}

// Close deletes the link and releases the netlink socket, once. It is safe
// after a partially failed LoadConfig, which is the path the server takes when
// the configuration is refused: the device must not survive it.
func (wg *kernelInterface) Close() error {
	wg.closeOnce.Do(func() { wg.closeErr = wg.close() })
	return wg.closeErr
}

func (wg *kernelInterface) close() error {
	var firstErr error

	link, err := netlink.LinkByName(wg.name)
	switch {
	case err == nil:
		if err := netlink.LinkDel(link); err != nil {
			firstErr = fmt.Errorf("deleting %s: %w", wg.name, err)
		}
	case isLinkNotFound(err):
		// already gone, which is what we wanted
	default:
		firstErr = fmt.Errorf("looking up %s: %w", wg.name, err)
	}

	if err := wg.client.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// isLinkNotFound reports whether err is the netlink "no such link" error.
func isLinkNotFound(err error) bool {
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound)
}
