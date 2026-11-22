//go:build linux

package awgnetlink

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Device returns the live state of one kernel device: keys, listen port and
// peers with endpoints, handshake times and counters.
//
// The kernel splits a large peer list (and a peer's allowed IPs) across several
// netlink messages; parseDevice merges them back into one device.
func (c *Client) Device(name string) (*wgtypes.Device, error) {
	enc := netlink.NewAttributeEncoder()
	enc.String(unix.WGDEVICE_A_IFNAME, name)
	attrs, err := enc.Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding the device query: %w", err)
	}

	msgs, err := c.execute(unix.WG_CMD_GET_DEVICE, netlink.Request|netlink.Dump, attrs)
	if err != nil {
		return nil, err
	}
	return parseDevice(msgs)
}

// parseDevice turns one or more WG_CMD_GET_DEVICE replies into a device.
//
// The structure follows wgctrl's Linux decoder (MIT); the only intentional
// differences are the AmneziaWG family and the v3 keepalive encoding.
func parseDevice(msgs []genetlink.Message) (*wgtypes.Device, error) {
	if len(msgs) == 0 {
		return nil, fmt.Errorf("the kernel returned no device")
	}

	var first wgtypes.Device
	knownPeers := make(map[wgtypes.Key]int)

	for i, m := range msgs {
		d, err := parseDeviceMessage(m)
		if err != nil {
			return nil, err
		}

		if i == 0 {
			first = *d
			for idx := range first.Peers {
				knownPeers[first.Peers[idx].PublicKey] = idx
			}
			continue
		}

		// Peers repeated in later messages only add allowed IPs.
		for _, peer := range d.Peers {
			if idx, ok := knownPeers[peer.PublicKey]; ok {
				first.Peers[idx].AllowedIPs = append(first.Peers[idx].AllowedIPs, peer.AllowedIPs...)
				continue
			}
			first.Peers = append(first.Peers, peer)
			knownPeers[peer.PublicKey] = len(first.Peers) - 1
		}
	}

	return &first, nil
}

// parseDeviceMessage parses a single netlink message.
func parseDeviceMessage(m genetlink.Message) (*wgtypes.Device, error) {
	ad, err := netlink.NewAttributeDecoder(m.Data)
	if err != nil {
		return nil, err
	}

	d := wgtypes.Device{Type: wgtypes.LinuxKernel}
	for ad.Next() {
		switch ad.Type() {
		case unix.WGDEVICE_A_IFNAME:
			d.Name = ad.String()
		case unix.WGDEVICE_A_PRIVATE_KEY:
			ad.Do(parseKey(&d.PrivateKey))
		case unix.WGDEVICE_A_PUBLIC_KEY:
			ad.Do(parseKey(&d.PublicKey))
		case unix.WGDEVICE_A_LISTEN_PORT:
			d.ListenPort = int(ad.Uint16())
		case unix.WGDEVICE_A_FWMARK:
			d.FirewallMark = int(ad.Uint32())
		case unix.WGDEVICE_A_PEERS:
			// Errors inside the nested decoders land in ad.Err() below.
			ad.Nested(func(peers *netlink.AttributeDecoder) error {
				d.Peers = make([]wgtypes.Peer, 0, peers.Len())
				for peers.Next() {
					peers.Nested(func(peer *netlink.AttributeDecoder) error {
						d.Peers = append(d.Peers, parsePeer(peer))
						return nil
					})
				}
				return nil
			})
		}
	}
	if err := ad.Err(); err != nil {
		return nil, err
	}
	return &d, nil
}

// parsePeer parses one peer's attributes.
func parsePeer(ad *netlink.AttributeDecoder) wgtypes.Peer {
	var p wgtypes.Peer
	for ad.Next() {
		switch ad.Type() {
		case unix.WGPEER_A_PUBLIC_KEY:
			ad.Do(parseKey(&p.PublicKey))
		case unix.WGPEER_A_PRESHARED_KEY:
			ad.Do(parseKey(&p.PresharedKey))
		case unix.WGPEER_A_ENDPOINT:
			p.Endpoint = &net.UDPAddr{}
			ad.Do(parseSockaddr(p.Endpoint))
		case unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL:
			// Family version 3 packs a u16 range into a u32; the interval is
			// its low half.
			p.PersistentKeepaliveInterval = time.Duration(uint16(ad.Uint32())) * time.Second
		case unix.WGPEER_A_LAST_HANDSHAKE_TIME:
			ad.Do(parseTimespec(&p.LastHandshakeTime))
		case unix.WGPEER_A_RX_BYTES:
			p.ReceiveBytes = int64(ad.Uint64())
		case unix.WGPEER_A_TX_BYTES:
			p.TransmitBytes = int64(ad.Uint64())
		case unix.WGPEER_A_ALLOWEDIPS:
			ad.Nested(parseAllowedIPs(&p.AllowedIPs))
		case unix.WGPEER_A_PROTOCOL_VERSION:
			p.ProtocolVersion = int(ad.Uint32())
		}
	}
	return p
}

// parseAllowedIPs parses the address/prefix entries of one peer.
func parseAllowedIPs(networks *[]net.IPNet) func(*netlink.AttributeDecoder) error {
	return func(ad *netlink.AttributeDecoder) error {
		*networks = make([]net.IPNet, 0, ad.Len())
		for ad.Next() {
			ad.Nested(func(entry *netlink.AttributeDecoder) error {
				var (
					network net.IPNet
					family  int
					bits    int
				)
				for entry.Next() {
					switch entry.Type() {
					case unix.WGALLOWEDIP_A_FAMILY:
						family = int(entry.Uint16())
					case unix.WGALLOWEDIP_A_IPADDR:
						entry.Do(parseAddr(&network.IP))
					case unix.WGALLOWEDIP_A_CIDR_MASK:
						bits = int(entry.Uint8())
					}
				}
				if err := entry.Err(); err != nil {
					return err
				}

				switch family {
				case unix.AF_INET:
					network.Mask = net.CIDRMask(bits, 32)
				case unix.AF_INET6:
					network.Mask = net.CIDRMask(bits, 128)
				default:
					return fmt.Errorf("allowed IP has unknown family %d", family)
				}

				*networks = append(*networks, network)
				return nil
			})
		}
		return nil
	}
}

// parseKey decodes a 32-byte key.
func parseKey(key *wgtypes.Key) func([]byte) error {
	return func(b []byte) error {
		k, err := wgtypes.NewKey(b)
		if err != nil {
			return err
		}
		*key = k
		return nil
	}
}

// parseAddr decodes an in_addr or in6_addr.
func parseAddr(ip *net.IP) func([]byte) error {
	return func(b []byte) error {
		switch len(b) {
		case net.IPv4len, net.IPv6len:
			*ip = append(make(net.IP, 0, len(b)), b...)
			return nil
		default:
			return fmt.Errorf("unexpected IP address size: %d", len(b))
		}
	}
}

// parseSockaddr decodes the raw sockaddr_in / sockaddr_in6 bytes of an
// endpoint. The port is in network byte order, the family in host order.
func parseSockaddr(endpoint *net.UDPAddr) func([]byte) error {
	return func(b []byte) error {
		if len(b) < 8 {
			return fmt.Errorf("endpoint has %d bytes, too short for a sockaddr", len(b))
		}
		port := int(binary.BigEndian.Uint16(b[2:4]))

		switch binary.LittleEndian.Uint16(b[0:2]) {
		case unix.AF_INET:
			*endpoint = net.UDPAddr{
				IP:   net.IP(append([]byte(nil), b[4:8]...)),
				Port: port,
			}
			return nil
		case unix.AF_INET6:
			if len(b) < 24 {
				return fmt.Errorf("IPv6 endpoint has %d bytes, too short for a sockaddr_in6", len(b))
			}
			*endpoint = net.UDPAddr{
				IP:   net.IP(append([]byte(nil), b[8:24]...)),
				Port: port,
			}
			return nil
		default:
			return fmt.Errorf("endpoint has unknown address family %d", binary.LittleEndian.Uint16(b[0:2]))
		}
	}
}

// parseTimespec decodes struct __kernel_timespec (two little-endian int64s).
// A zero timespec means "never", which stays the zero time.Time.
func parseTimespec(t *time.Time) func([]byte) error {
	return func(b []byte) error {
		if len(b) < 16 {
			return fmt.Errorf("handshake time has %d bytes, want 16", len(b))
		}
		seconds := int64(binary.LittleEndian.Uint64(b[0:8]))
		nanos := int64(binary.LittleEndian.Uint64(b[8:16]))
		if seconds != 0 {
			*t = time.Unix(seconds, nanos)
		}
		return nil
	}
}
