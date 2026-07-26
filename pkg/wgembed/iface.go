package wgembed

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var ErrUnsupportedPlatform = errors.New("amneziawg-embed requires Linux")

type WireGuardInterface interface {
	LoadConfig(*ConfigFile) error
	AddPeer(publicKey, presharedKey string, addressCIDR []string) error
	ListPeers() ([]wgtypes.Peer, error)
	RemovePeer(publicKey string) error
	PublicKey() (string, error)
	Ping() error
	Close() error
}

type Options struct {
	InterfaceName     string
	AllowKernelModule bool
}

type ConfigFile struct {
	Interface IfaceConfig
	Peers     []PeerConfig
}
type IfaceConfig struct {
	PrivateKey string
	Address    []string
	ListenPort *int
	DNS        []string
	MTU        *int
	Amnezia    AmneziaConfig
}
type PeerConfig struct {
	PublicKey  string
	AllowedIPs []string
	Endpoint   *string
}

// AmneziaConfig uses pointers so omitted values remain distinct from zero.
type AmneziaConfig struct {
	JC, JMin, JMax                                                                                                *uint32
	S1, S2, S3, S4                                                                                                *uint32
	H1, H2, H3, H4                                                                                                *string
	I1, I2, I3, I4, I5                                                                                            *string
	HeaderProtectionKey                                                                                           string
	ContentPaddingAddition, RekeyAfterTime, RekeyTimeout, RejectAfterTime, KeepaliveTimeout, MaxHandshakeAttempts *string
}

func New(interfaceName string) (WireGuardInterface, error) {
	return NewWithOpts(Options{InterfaceName: interfaceName})
}

func (c *ConfigFile) validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.Interface.PrivateKey != "" {
		if _, err := wgtypes.ParseKey(c.Interface.PrivateKey); err != nil {
			return errors.New("private key is invalid")
		}
	}
	if c.Interface.ListenPort != nil && (*c.Interface.ListenPort < 0 || *c.Interface.ListenPort > 65535) {
		return errors.New("listen port is invalid")
	}
	for _, a := range c.Interface.Address {
		if _, err := netip.ParsePrefix(a); err != nil {
			return errors.New("interface address is invalid")
		}
	}
	for _, p := range c.Peers {
		if _, err := wgtypes.ParseKey(p.PublicKey); err != nil {
			return errors.New("peer public key is invalid")
		}
		for _, a := range p.AllowedIPs {
			if _, err := netip.ParsePrefix(a); err != nil {
				return errors.New("peer allowed IP is invalid")
			}
		}
	}
	return validateAWG(c.Interface.Amnezia)
}

func validateAWG(a AmneziaConfig) error {
	if a.HeaderProtectionKey != "" {
		if _, err := wgtypes.ParseKey(a.HeaderProtectionKey); err != nil {
			return errors.New("header protection key is invalid")
		}
	}
	if a.JMin != nil && a.JMax != nil && *a.JMin > *a.JMax {
		return errors.New("jmin must be <= jmax")
	}
	for n, v := range map[string]*string{"h1": a.H1, "h2": a.H2, "h3": a.H3, "h4": a.H4, "i1": a.I1, "i2": a.I2, "i3": a.I3, "i4": a.I4, "i5": a.I5, "content_padding_addition": a.ContentPaddingAddition, "rekey_after_time": a.RekeyAfterTime, "rekey_timeout": a.RekeyTimeout, "reject_after_time": a.RejectAfterTime, "keepalive_timeout": a.KeepaliveTimeout, "max_handshake_attempts": a.MaxHandshakeAttempts} {
		if v != nil && strings.TrimSpace(*v) == "" {
			return errors.New(n + " must not be empty")
		}
	}
	return nil
}

func u32(v *uint32) string {
	if v == nil {
		return ""
	}
	return strconv.FormatUint(uint64(*v), 10)
}
