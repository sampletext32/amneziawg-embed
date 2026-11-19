package wgembed

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// headerCipherNonceSize is the number of leading bytes AmneziaWG's header
// cipher takes as its nonce. Padding smaller than this would encrypt real
// header bytes, so a header protection key requires S1-S4 of at least this.
const headerCipherNonceSize = 12

// AmneziaConfig holds the AmneziaWG parameters of an interface. Pointers keep
// "not set" distinct from zero: AmneziaWG treats a missing value as 0, but a
// caller that explicitly asks for 0 must be able to say so, and an empty string
// would otherwise be sent as a key with no value.
type AmneziaConfig struct {
	// Junk packets: Jc of them, each Jmin..Jmax bytes, before every handshake.
	JC, JMin, JMax *uint32

	// Padding of the init, response, cookie and transport messages. They have
	// to match on both sides.
	S1, S2, S3, S4 *uint32

	// Uint32 ranges ("123-456" or "1234") at the start of each message type.
	// They have to match on both sides.
	H1, H2, H3, H4 *string

	// Custom signature packets, sent in order before every handshake.
	I1, I2, I3, I4, I5 *string

	// HeaderProtectionKey encrypts the 12-byte packet header. It is
	// server-side and part of the configuration: it must be persisted, not
	// regenerated, or every client stops connecting.
	HeaderProtectionKey string

	ContentPaddingAddition *string
	RekeyAfterTime         *string
	RekeyTimeout           *string
	RejectAfterTime        *string
	KeepaliveTimeout       *string
	MaxHandshakeAttempts   *string
}

// amneziaField is one parameter and the value it would be sent with.
type amneziaField struct {
	key   string
	value string
}

// amneziaFields is every parameter in the order it is sent, so that the output
// is stable and a log line or a test can compare it. An empty value is not
// sent at all.
func (a AmneziaConfig) amneziaFields() []amneziaField {
	u32 := func(v *uint32) string {
		if v == nil {
			return ""
		}
		return strconv.FormatUint(uint64(*v), 10)
	}
	s := func(v *string) string {
		if v == nil {
			return ""
		}
		return *v
	}

	fields := []amneziaField{
		{"jc", u32(a.JC)},
		{"jmin", u32(a.JMin)},
		{"jmax", u32(a.JMax)},
		{"s1", u32(a.S1)},
		{"s2", u32(a.S2)},
		{"s3", u32(a.S3)},
		{"s4", u32(a.S4)},
		{"h1", s(a.H1)},
		{"h2", s(a.H2)},
		{"h3", s(a.H3)},
		{"h4", s(a.H4)},
		{"i1", s(a.I1)},
		{"i2", s(a.I2)},
		{"i3", s(a.I3)},
		{"i4", s(a.I4)},
		{"i5", s(a.I5)},
		{"content_padding_addition", s(a.ContentPaddingAddition)},
		{"rekey_after_time", s(a.RekeyAfterTime)},
		{"rekey_timeout", s(a.RekeyTimeout)},
		{"reject_after_time", s(a.RejectAfterTime)},
		{"keepalive_timeout", s(a.KeepaliveTimeout)},
		{"max_handshake_attempts", s(a.MaxHandshakeAttempts)},
	}
	if a.HeaderProtectionKey != "" {
		// ParseKey has already been checked by validate; the zero value keeps
		// this list-building function total.
		var encoded string
		if key, err := wgtypes.ParseKey(a.HeaderProtectionKey); err == nil {
			encoded = hex.EncodeToString(key[:])
		}
		fields = append(fields, struct {
			key   string
			value string
		}{"header_protection_key", encoded})
	}
	return fields
}

// IsZero reports whether no AmneziaWG parameter is set at all. Such an
// interface behaves as plain WireGuard: the device uses the standard message
// types and no padding.
func (a AmneziaConfig) IsZero() bool {
	for _, field := range a.amneziaFields() {
		if field.value != "" {
			return false
		}
	}
	return true
}

// validate rejects what the device would reject later, so that a typo in the
// configuration is a startup error rather than a handshake that never happens.
func (a AmneziaConfig) validate() error {
	if err := a.validateValues(); err != nil {
		return err
	}

	if a.HeaderProtectionKey != "" {
		if _, err := wgtypes.ParseKey(a.HeaderProtectionKey); err != nil {
			return errors.New("header protection key is invalid")
		}
		for _, padding := range []struct {
			name  string
			value *uint32
		}{{"s1", a.S1}, {"s2", a.S2}, {"s3", a.S3}, {"s4", a.S4}} {
			if padding.value != nil && *padding.value < headerCipherNonceSize {
				return fmt.Errorf("header protection needs %s of at least %d", padding.name, headerCipherNonceSize)
			}
		}
	}
	return nil
}

// validateValues checks the values themselves, without the rules that only
// apply when header protection is on.
func (a AmneziaConfig) validateValues() error {
	if a.JMin != nil && a.JMax != nil && *a.JMin > *a.JMax {
		return errors.New("jmin must not be larger than jmax")
	}
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"h1", a.H1}, {"h2", a.H2}, {"h3", a.H3}, {"h4", a.H4},
		{"i1", a.I1}, {"i2", a.I2}, {"i3", a.I3}, {"i4", a.I4}, {"i5", a.I5},
		{"content_padding_addition", a.ContentPaddingAddition},
		{"rekey_after_time", a.RekeyAfterTime},
		{"rekey_timeout", a.RekeyTimeout},
		{"reject_after_time", a.RejectAfterTime},
		{"keepalive_timeout", a.KeepaliveTimeout},
		{"max_handshake_attempts", a.MaxHandshakeAttempts},
	} {
		if field.value != nil && strings.TrimSpace(*field.value) == "" {
			return fmt.Errorf("%s must not be empty", field.name)
		}
	}
	return nil
}

// uapi renders the parameters as a UAPI "set" body. The device merges what it
// is given, so sending only these lines leaves the keys, the peers and the
// listen port as they are. A trailing blank line ends the operation.
func (a AmneziaConfig) uapi() (string, error) {
	if err := a.validate(); err != nil {
		return "", err
	}

	var b strings.Builder
	for _, field := range a.amneziaFields() {
		if field.value != "" {
			b.WriteString(field.key + "=" + field.value + "\n")
		}
	}
	if b.Len() == 0 {
		return "", nil
	}
	b.WriteString("\n")
	return b.String(), nil
}
