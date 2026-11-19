package wgembed

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AmneziaConfig holds the AmneziaWG parameters of an interface. Pointers keep
// "not set" distinct from zero: AmneziaWG treats a missing value as 0, but a
// caller that explicitly asks for 0 must be able to say so, and an empty string
// would otherwise be sent as a key with no value.
type AmneziaConfig struct {
	// Junk packets: Jc of them, each Jmin..Jmax bytes, before every handshake.
	JC, JMin, JMax *uint32

	// Padding of the init, response, cookie and transport messages. They have
	// to match on both sides; header protection needs at least 12.
	S1, S2, S3, S4 *uint32

	// Uint32 ranges ("123-456" or "1234") at the start of each message type.
	// They have to match on both sides.
	H1, H2, H3, H4 *string

	// Custom signature packets, sent in order before every handshake.
	I1, I2, I3, I4, I5 *string

	// HeaderProtectionKey encrypts the 12-byte header. Server-side; the key is
	// part of the configuration, so it must be persisted, not regenerated.
	HeaderProtectionKey string

	ContentPaddingAddition *string
	RekeyAfterTime         *string
	RekeyTimeout           *string
	RejectAfterTime        *string
	KeepaliveTimeout       *string
	MaxHandshakeAttempts   *string
}

// IsZero reports whether no AmneziaWG parameter is set at all. Such an
// interface behaves as plain WireGuard: the device then uses the standard
// message types and no padding.
func (a AmneziaConfig) IsZero() bool {
	return a.JC == nil && a.JMin == nil && a.JMax == nil &&
		a.S1 == nil && a.S2 == nil && a.S3 == nil && a.S4 == nil &&
		a.H1 == nil && a.H2 == nil && a.H3 == nil && a.H4 == nil &&
		a.I1 == nil && a.I2 == nil && a.I3 == nil && a.I4 == nil && a.I5 == nil &&
		a.HeaderProtectionKey == "" && a.ContentPaddingAddition == nil &&
		a.RekeyAfterTime == nil && a.RekeyTimeout == nil &&
		a.RejectAfterTime == nil && a.KeepaliveTimeout == nil &&
		a.MaxHandshakeAttempts == nil
}

// validate rejects what the device would reject later, so that a typo in the
// configuration is a startup error rather than a failed handshake.
func (a AmneziaConfig) validate() error {
	if a.JMin != nil && a.JMax != nil && *a.JMin > *a.JMax {
		return errors.New("jmin must not be larger than jmax")
	}
	if a.HeaderProtectionKey != "" {
		if _, err := wgtypes.ParseKey(a.HeaderProtectionKey); err != nil {
			return errors.New("header protection key is invalid")
		}
		// The header cipher takes its nonce from the first 12 bytes of the
		// packet, so smaller padding would encrypt real header bytes.
		for name, value := range map[string]*uint32{"s1": a.S1, "s2": a.S2, "s3": a.S3, "s4": a.S4} {
			if value != nil && *value < headerCipherNonceSize {
				return fmt.Errorf("header protection needs %s >= %d", name, headerCipherNonceSize)
			}
		}
	}
	for name, value := range map[string]*string{
		"h1": a.H1, "h2": a.H2, "h3": a.H3, "h4": a.H4,
		"i1": a.I1, "i2": a.I2, "i3": a.I3, "i4": a.I4, "i5": a.I5,
		"content_padding_addition": a.ContentPaddingAddition,
		"rekey_after_time":         a.RekeyAfterTime,
		"rekey_timeout":            a.RekeyTimeout,
		"reject_after_time":        a.RejectAfterTime,
		"keepalive_timeout":        a.KeepaliveTimeout,
		"max_handshake_attempts":   a.MaxHandshakeAttempts,
	} {
		if value != nil && strings.TrimSpace(*value) == "" {
			return fmt.Errorf("%s must not be empty", name)
		}
	}
	return nil
}

// headerCipherNonceSize mirrors amneziawg-go's HeaderCipherNonceSize: the
// header cipher reads its nonce from the first bytes of the packet.
const headerCipherNonceSize = 12

// uapi renders the parameters as a UAPI "set" body. The device merges what it
// is given, so sending only these lines leaves keys, peers and listen port as
// they are. A trailing blank line terminates the operation.
func (a AmneziaConfig) uapi() (string, error) {
	if err := a.validate(); err != nil {
		return "", err
	}

	var b strings.Builder
	put := func(key, value string) {
		if value != "" {
			b.WriteString(key + "=" + value + "\n")
		}
	}
	u32 := func(v *uint32) string {
		if v == nil {
			return ""
		}
		return strconv.FormatUint(uint64(*v), 10)
	}

	put("jc", u32(a.JC))
	put("jmin", u32(a.JMin))
	put("jmax", u32(a.JMax))
	put("s1", u32(a.S1))
	put("s2", u32(a.S2))
	put("s3", u32(a.S3))
	put("s4", u32(a.S4))

	for key, value := range map[string]*string{
		"h1": a.H1, "h2": a.H2, "h3": a.H3, "h4": a.H4,
		"i1": a.I1, "i2": a.I2, "i3": a.I3, "i4": a.I4, "i5": a.I5,
		"content_padding_addition": a.ContentPaddingAddition,
		"rekey_after_time":         a.RekeyAfterTime,
		"rekey_timeout":            a.RekeyTimeout,
		"reject_after_time":        a.RejectAfterTime,
		"keepalive_timeout":        a.KeepaliveTimeout,
		"max_handshake_attempts":   a.MaxHandshakeAttempts,
	} {
		if value != nil {
			put(key, *value)
		}
	}

	if a.HeaderProtectionKey != "" {
		key, err := wgtypes.ParseKey(a.HeaderProtectionKey)
		if err != nil {
			return "", errors.New("header protection key is invalid")
		}
		put("header_protection_key", hex.EncodeToString(key[:]))
	}

	if b.Len() == 0 {
		return "", nil
	}
	b.WriteString("\n")
	return b.String(), nil
}
