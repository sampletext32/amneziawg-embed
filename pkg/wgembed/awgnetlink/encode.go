//go:build linux

package awgnetlink

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AmneziaConfig is the AmneziaWG parameter set of a device. It mirrors
// wgembed.AmneziaConfig field for field; the package keeps its own copy so that
// wgembed can depend on this package without an import cycle.
//
// Pointers distinguish "not set" from an explicit zero, exactly as the userspace
// device does: a missing value is left at the module's default.
type AmneziaConfig struct {
	JC, JMin, JMax *uint32

	S1, S2, S3, S4 *uint32

	// Uint32 ranges ("1234" or "123-456"); encoded as u64 lo | hi<<32.
	H1, H2, H3, H4 *string

	I1, I2, I3, I4, I5 *string

	HeaderProtectionKey string

	RandomTrailers bool
	DisableCookies bool

	ContentPaddingAddition                        *string
	RekeyAfterTime, RekeyTimeout, RejectAfterTime *string
	KeepaliveTimeout, MaxHandshakeAttempts        *string
}

// IsZero reports whether no parameter is set at all, in which case the kernel
// device keeps its defaults: standard message types, no padding, plain
// WireGuard on the wire.
func (a AmneziaConfig) IsZero() bool {
	for _, v := range []*uint32{a.JC, a.JMin, a.JMax, a.S1, a.S2, a.S3, a.S4} {
		if v != nil {
			return false
		}
	}
	for _, v := range []*string{
		a.H1, a.H2, a.H3, a.H4,
		a.I1, a.I2, a.I3, a.I4, a.I5,
		a.ContentPaddingAddition,
		a.RekeyAfterTime, a.RekeyTimeout, a.RejectAfterTime,
		a.KeepaliveTimeout, a.MaxHandshakeAttempts,
	} {
		if v != nil && *v != "" {
			return false
		}
	}
	return a.HeaderProtectionKey == "" && !a.RandomTrailers && !a.DisableCookies
}

// validate rejects what the module's netlink types cannot carry, before a
// single attribute is sent. The server validates the profile as well; this is
// the kernel-specific half (u16 widths and range packing), which the userspace
// device does not share.
func (a AmneziaConfig) validate() error {
	for _, field := range []struct {
		name  string
		value *uint32
	}{{"jc", a.JC}, {"jmin", a.JMin}, {"jmax", a.JMax}, {"s1", a.S1}, {"s2", a.S2}, {"s3", a.S3}, {"s4", a.S4}} {
		if field.value != nil && *field.value > 65535 {
			return fmt.Errorf("%s is %d, which does not fit the kernel module's 16-bit attribute", field.name, *field.value)
		}
	}
	if a.JMin != nil && a.JMax != nil && *a.JMin > *a.JMax {
		return fmt.Errorf("jmin (%d) is larger than jmax (%d)", *a.JMin, *a.JMax)
	}

	for _, field := range []struct {
		name  string
		value *string
	}{{"h1", a.H1}, {"h2", a.H2}, {"h3", a.H3}, {"h4", a.H4}} {
		if field.value == nil {
			continue
		}
		if _, _, err := parseUintRange(field.name, *field.value); err != nil {
			return err
		}
	}

	for _, field := range []struct {
		name  string
		value *string
	}{
		{"content_padding_addition", a.ContentPaddingAddition},
		{"rekey_after_time", a.RekeyAfterTime},
		{"rekey_timeout", a.RekeyTimeout},
		{"reject_after_time", a.RejectAfterTime},
		{"keepalive_timeout", a.KeepaliveTimeout},
		{"max_handshake_attempts", a.MaxHandshakeAttempts},
	} {
		if field.value == nil {
			continue
		}
		lo, hi, err := parseUintRange(field.name, *field.value)
		if err != nil {
			return err
		}
		if lo > 65535 || hi > 65535 {
			return fmt.Errorf("%s (%q) does not fit the kernel module's 16-bit range", field.name, *field.value)
		}
	}

	for _, field := range []struct {
		name  string
		value *string
	}{{"i1", a.I1}, {"i2", a.I2}, {"i3", a.I3}, {"i4", a.I4}, {"i5", a.I5}} {
		if field.value != nil && *field.value == "" {
			return fmt.Errorf("%s is empty", field.name)
		}
	}

	if a.HeaderProtectionKey != "" {
		if _, err := wgtypes.ParseKey(a.HeaderProtectionKey); err != nil {
			return fmt.Errorf("header protection key is invalid: %w", err)
		}
		for _, field := range []struct {
			name  string
			value *uint32
		}{{"s1", a.S1}, {"s2", a.S2}, {"s3", a.S3}, {"s4", a.S4}} {
			if field.value != nil && *field.value < headerCipherNonceSize {
				return fmt.Errorf("header protection needs %s of at least %d", field.name, headerCipherNonceSize)
			}
		}
	}
	return nil
}

// headerCipherNonceSize is the 12-byte nonce of the header cipher: padding
// smaller than this would encrypt real header bytes.
const headerCipherNonceSize = 12

// encodeAmnezia writes the AWG device attributes into enc.
func encodeAmnezia(enc *netlink.AttributeEncoder, a AmneziaConfig) error {
	putU16(enc, wgdeviceAJC, a.JC)
	putU16(enc, wgdeviceAJMin, a.JMin)
	putU16(enc, wgdeviceAJMax, a.JMax)
	putU16(enc, wgdeviceAS1, a.S1)
	putU16(enc, wgdeviceAS2, a.S2)
	putU16(enc, wgdeviceAS3, a.S3)
	putU16(enc, wgdeviceAS4, a.S4)

	// H1-H4 are a packed u32_range_t: low in the low 32 bits, high in the high
	// 32. The module compares them against the four-byte message type.
	for _, field := range []struct {
		attr  uint16
		value *string
	}{
		{wgdeviceAH1, a.H1},
		{wgdeviceAH2, a.H2},
		{wgdeviceAH3, a.H3},
		{wgdeviceAH4, a.H4},
	} {
		if field.value == nil {
			continue
		}
		lo, hi, err := parseUintRange("h", *field.value)
		if err != nil {
			return err
		}
		enc.Uint64(field.attr, uint64(lo)|uint64(hi)<<32)
	}

	// Signature packets are NUL-terminated strings in the module's own tag
	// language; it parses them exactly like amneziawg-go does.
	for _, field := range []struct {
		attr  uint16
		value *string
	}{
		{wgdeviceAI1, a.I1},
		{wgdeviceAI2, a.I2},
		{wgdeviceAI3, a.I3},
		{wgdeviceAI4, a.I4},
		{wgdeviceAI5, a.I5},
	} {
		if field.value != nil {
			enc.String(field.attr, *field.value)
		}
	}

	if a.HeaderProtectionKey != "" {
		key, err := wgtypes.ParseKey(a.HeaderProtectionKey)
		if err != nil {
			return fmt.Errorf("header protection key is invalid: %w", err)
		}
		enc.Bytes(wgdeviceAHeaderProtectionKey, key[:])
	}

	// Content padding and the timers are u16 ranges packed into a u32:
	// lo | hi<<16.
	for _, field := range []struct {
		attr  uint16
		name  string
		value *string
	}{
		{wgdeviceAContentPaddingAddition, "content_padding_addition", a.ContentPaddingAddition},
		{wgdeviceARekeyAfterTime, "rekey_after_time", a.RekeyAfterTime},
		{wgdeviceARekeyTimeout, "rekey_timeout", a.RekeyTimeout},
		{wgdeviceARejectAfterTime, "reject_after_time", a.RejectAfterTime},
		{wgdeviceAKeepaliveTimeout, "keepalive_timeout", a.KeepaliveTimeout},
		{wgdeviceAMaxHandshakeAttempts, "max_handshake_attempts", a.MaxHandshakeAttempts},
	} {
		if field.value == nil {
			continue
		}
		lo, hi, err := parseUintRange(field.name, *field.value)
		if err != nil {
			return err
		}
		enc.Uint32(field.attr, uint32(uint16(lo))|uint32(uint16(hi))<<16)
	}

	if a.RandomTrailers {
		enc.Uint8(wgdeviceARandomTrailers, 1)
	}
	if a.DisableCookies {
		enc.Uint8(wgdeviceADisableCookies, 1)
	}
	return nil
}

// putU16 writes a 16-bit device attribute when the value is set.
func putU16(enc *netlink.AttributeEncoder, attr uint16, value *uint32) {
	if value != nil {
		enc.Uint16(attr, uint16(*value))
	}
}

// parseUintRange accepts what AmneziaWG accepts for a range: one decimal
// number, or two separated by a single "-".
func parseUintRange(name, value string) (uint32, uint32, error) {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, fmt.Errorf("%s: %q is not a number or a range", name, value)
	}
	lo, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %q is not a number or a range", name, value)
	}
	if len(parts) == 1 {
		return uint32(lo), uint32(lo), nil
	}
	hi, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %q is not a number or a range", name, value)
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("%s: %q ends before it begins", name, value)
	}
	return uint32(lo), uint32(hi), nil
}

// packedSeconds encodes a keepalive interval as the v3 attribute expects it: a
// u16 range packed into u32. A single value N becomes the range N-N.
func packedSeconds(interval time.Duration) (uint32, error) {
	seconds := int64(interval / time.Second)
	if seconds < 0 || seconds > 65535 {
		return 0, fmt.Errorf("persistent keepalive %s does not fit the kernel module's 16-bit range", interval)
	}
	return uint32(seconds) | uint32(seconds)<<16, nil
}

// encodeSockaddr returns the raw sockaddr_in or sockaddr_in6 bytes of an
// endpoint, in the layout the kernel's policy expects.
func encodeSockaddr(endpoint *net.UDPAddr) func() ([]byte, error) {
	return func() ([]byte, error) {
		ip4 := endpoint.IP.To4()
		if ip4 != nil {
			b := make([]byte, 16) // sizeof(struct sockaddr_in)
			binary.LittleEndian.PutUint16(b[0:2], unix.AF_INET)
			binary.BigEndian.PutUint16(b[2:4], uint16(endpoint.Port))
			copy(b[4:8], ip4)
			return b, nil
		}
		ip16 := endpoint.IP.To16()
		if ip16 == nil {
			return nil, fmt.Errorf("invalid endpoint IP %v", endpoint.IP)
		}
		b := make([]byte, 28) // sizeof(struct sockaddr_in6)
		binary.LittleEndian.PutUint16(b[0:2], unix.AF_INET6)
		binary.BigEndian.PutUint16(b[2:4], uint16(endpoint.Port))
		copy(b[8:24], ip16)
		return b, nil
	}
}
