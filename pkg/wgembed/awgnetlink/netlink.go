//go:build linux

// Package awgnetlink is a minimal generic-netlink client for the AmneziaWG
// kernel module.
//
// It exists because neither wgctrl nor its forks can drive that module: wgctrl
// hardcodes the stock "wireguard" family and version 1 and has no fields for
// the AmneziaWG attributes, and amneziawg-tools' netlink encoding covers only
// the AWG 1.x surface. This package speaks the family "amneziawg", version 3,
// as defined by amneziawg-linux-kernel-module's src/uapi/wireguard.h.
//
// The attribute numbers and wire types below were taken from the pinned module
// sources (v3.1.20261113-02) and tools (v3.1.20260812): the device_policy and
// peer_policy arrays in src/netlink.c, the encoding in src/ipc-linux.h and the
// range helpers in src/type.h.
package awgnetlink

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// genlName is WG_GENL_NAME in the module's uapi/wireguard.h. Note that
	// unix.WG_GENL_NAME is "wireguard" - the stock family - and is not it.
	genlName = "amneziawg"

	// minFamilyVersion is WG_GENL_VERSION. Version 1 and 2 encode H1-H4
	// differently (u32 and a string); this client only implements version 3 and
	// refuses older modules rather than guessing.
	minFamilyVersion = 3
)

// AmneziaWG device attributes that the Linux UAPI headers do not know.
const (
	wgdeviceAJC                     = 9
	wgdeviceAJMin                   = 10
	wgdeviceAJMax                   = 11
	wgdeviceAS1                     = 12
	wgdeviceAS2                     = 13
	wgdeviceAH1                     = 14
	wgdeviceAH2                     = 15
	wgdeviceAH3                     = 16
	wgdeviceAH4                     = 17
	wgdeviceAS3                     = 19
	wgdeviceAS4                     = 20
	wgdeviceAI1                     = 21
	wgdeviceAI2                     = 22
	wgdeviceAI3                     = 23
	wgdeviceAI4                     = 24
	wgdeviceAI5                     = 25
	wgdeviceAHeaderProtectionKey    = 26
	wgdeviceAContentPaddingAddition = 27
	wgdeviceARekeyAfterTime         = 28
	wgdeviceARekeyTimeout           = 29
	wgdeviceARejectAfterTime        = 30
	wgdeviceAKeepaliveTimeout       = 31
	wgdeviceAMaxHandshakeAttempts   = 32
	wgdeviceARandomTrailers         = 33
	wgdeviceADisableCookies         = 34
)

// Client talks to the amneziawg generic-netlink family.
type Client struct {
	c      *genetlink.Conn
	family genetlink.Family
}

// New opens the generic-netlink family. It fails with an actionable message
// when the module is not loaded or too old.
func New() (*Client, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("opening generic netlink: %w", err)
	}

	// Best effort, like wgctrl: strict validation catches a malformed request
	// instead of letting the kernel ignore it.
	for _, o := range []netlink.ConnOption{
		netlink.ExtendedAcknowledge,
		netlink.GetStrictCheck,
	} {
		_ = c.SetOption(o, true)
	}

	f, err := c.GetFamily(genlName)
	if err != nil {
		_ = c.Close()
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("the amneziawg kernel module is not loaded on this node; install amneziawg-dkms there")
		}
		return nil, fmt.Errorf("looking up the %q netlink family: %w", genlName, err)
	}
	if f.Version < minFamilyVersion {
		_ = c.Close()
		return nil, fmt.Errorf(
			"the amneziawg kernel module is too old: netlink family %q reports version %d, need at least %d; update amneziawg-dkms on this node",
			genlName, f.Version, minFamilyVersion)
	}

	return &Client{c: c, family: f}, nil
}

// FamilyVersion returns the netlink family version reported by the module, for
// logging.
func (c *Client) FamilyVersion() uint8 { return c.family.Version }

// Close releases the netlink socket.
func (c *Client) Close() error { return c.c.Close() }

// execute sends one command to the family and returns the reply messages. A
// failure names the operation, so a kernel error is read in context rather than
// as a bare errno.
func (c *Client) execute(command uint8, flags netlink.HeaderFlags, attrs []byte) ([]genetlink.Message, error) {
	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: command,
			Version: c.family.Version,
		},
		Data: attrs,
	}

	msgs, err := c.c.Execute(msg, c.family.ID, flags)
	if err == nil {
		return msgs, nil
	}

	var oerr *netlink.OpError
	if errors.As(err, &oerr) {
		return nil, fmt.Errorf("amneziawg netlink: %s: %w", commandName(command), oerr.Err)
	}
	return nil, fmt.Errorf("amneziawg netlink: %s: %w", commandName(command), err)
}

// commandName is the operation half of an error message.
func commandName(command uint8) string {
	switch command {
	case unix.WG_CMD_GET_DEVICE:
		return "get device"
	case unix.WG_CMD_SET_DEVICE:
		return "set device"
	default:
		return fmt.Sprintf("command %d", command)
	}
}

// ConfigureDevice applies the stock WireGuard fields of cfg: private key,
// listen port, firewall mark and peers. The AmneziaWG attributes are a separate
// message (SetAmnezia); the kernel merges both into the same device.
//
// Large peer lists are not split into batches: this client is used by a server
// that adds one peer at a time, with a handful of allowed IPs each.
func (c *Client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	enc := netlink.NewAttributeEncoder()
	enc.String(unix.WGDEVICE_A_IFNAME, name)

	if cfg.PrivateKey != nil {
		enc.Bytes(unix.WGDEVICE_A_PRIVATE_KEY, (*cfg.PrivateKey)[:])
	}
	if cfg.ListenPort != nil {
		enc.Uint16(unix.WGDEVICE_A_LISTEN_PORT, uint16(*cfg.ListenPort))
	}
	if cfg.FirewallMark != nil {
		enc.Uint32(unix.WGDEVICE_A_FWMARK, uint32(*cfg.FirewallMark))
	}
	if cfg.ReplacePeers {
		enc.Uint32(unix.WGDEVICE_A_FLAGS, unix.WGDEVICE_F_REPLACE_PEERS)
	}

	if len(cfg.Peers) > 0 {
		// Errors inside the nested encoders are recorded by the encoder and
		// returned from Encode; there is no error to check here.
		enc.Nested(unix.WGDEVICE_A_PEERS, func(peers *netlink.AttributeEncoder) error {
			for i, p := range cfg.Peers {
				peer := p
				peers.Nested(uint16(i), encodePeer(peer))
			}
			return nil
		})
	}

	attrs, err := enc.Encode()
	if err != nil {
		return fmt.Errorf("encoding the device configuration: %w", err)
	}
	_, err = c.execute(unix.WG_CMD_SET_DEVICE, netlink.Request|netlink.Acknowledge, attrs)
	return err
}

// SetAmnezia applies the AmneziaWG parameters of the device: padding, header
// ranges, signature packets, header protection, content padding and timers.
// Peers and the stock fields are left as they are; the kernel merges updates.
func (c *Client) SetAmnezia(name string, a AmneziaConfig) error {
	if a.IsZero() {
		return nil
	}
	if err := a.validate(); err != nil {
		return err
	}

	enc := netlink.NewAttributeEncoder()
	enc.String(unix.WGDEVICE_A_IFNAME, name)

	if err := encodeAmnezia(enc, a); err != nil {
		return err
	}

	attrs, err := enc.Encode()
	if err != nil {
		return fmt.Errorf("encoding the AmneziaWG parameters: %w", err)
	}
	_, err = c.execute(unix.WG_CMD_SET_DEVICE, netlink.Request|netlink.Acknowledge, attrs)
	return err
}

// encodePeer encodes one peer, including the flags the kernel expects as a
// single u32 attribute.
func encodePeer(p wgtypes.PeerConfig) func(*netlink.AttributeEncoder) error {
	return func(enc *netlink.AttributeEncoder) error {
		enc.Bytes(unix.WGPEER_A_PUBLIC_KEY, p.PublicKey[:])

		var flags uint32
		if p.Remove {
			flags |= unix.WGPEER_F_REMOVE_ME
		}
		if p.ReplaceAllowedIPs {
			flags |= unix.WGPEER_F_REPLACE_ALLOWEDIPS
		}
		if p.UpdateOnly {
			flags |= unix.WGPEER_F_UPDATE_ONLY
		}
		if flags != 0 {
			enc.Uint32(unix.WGPEER_A_FLAGS, flags)
		}

		if p.PresharedKey != nil {
			enc.Bytes(unix.WGPEER_A_PRESHARED_KEY, (*p.PresharedKey)[:])
		}
		if p.Endpoint != nil {
			// The endpoint is a raw sockaddr, not a nested attribute.
			enc.Do(unix.WGPEER_A_ENDPOINT, encodeSockaddr(p.Endpoint))
		}
		if p.PersistentKeepaliveInterval != nil {
			// Family version 3 takes a u32: a packed u16 range, even when it is
			// one number. wgctrl's u16 here is what the module rejects.
			seconds, err := packedSeconds(*p.PersistentKeepaliveInterval)
			if err != nil {
				return err
			}
			enc.Uint32(unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, seconds)
		}

		if len(p.AllowedIPs) > 0 {
			enc.Nested(unix.WGPEER_A_ALLOWEDIPS, func(allowed *netlink.AttributeEncoder) error {
				for i, ipnet := range p.AllowedIPs {
					network := ipnet
					allowed.Nested(uint16(i), encodeAllowedIP(network))
				}
				return nil
			})
		}
		return nil
	}
}

// encodeAllowedIP encodes one entry of the allowed-IPs array: family, address
// and prefix length.
func encodeAllowedIP(ipnet net.IPNet) func(*netlink.AttributeEncoder) error {
	return func(enc *netlink.AttributeEncoder) error {
		family := uint16(unix.AF_INET6)
		if ipnet.IP.To4() != nil {
			family = unix.AF_INET
		} else if ipnet.IP.To16() == nil {
			return fmt.Errorf("invalid allowed IP %v", ipnet.IP)
		}

		enc.Uint16(unix.WGALLOWEDIP_A_FAMILY, family)
		if family == unix.AF_INET {
			enc.Bytes(unix.WGALLOWEDIP_A_IPADDR, ipnet.IP.To4())
		} else {
			enc.Bytes(unix.WGALLOWEDIP_A_IPADDR, ipnet.IP.To16())
		}
		ones, _ := ipnet.Mask.Size()
		enc.Uint8(unix.WGALLOWEDIP_A_CIDR_MASK, uint8(ones))
		return nil
	}
}
