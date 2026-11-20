package wgembed

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// headerCipherNonceSize is the number of leading bytes AmneziaWG's header
	// cipher takes as its nonce. Padding smaller than this would encrypt real
	// header bytes, so a header protection key requires S1-S4 of at least this.
	headerCipherNonceSize = 12

	// maxPaddingSize is the largest S1-S4 the device accepts: it parses them as
	// 16-bit values, so anything larger fails when the parameters are applied
	// rather than when they are read.
	maxPaddingSize = 65535
)

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

	// HeaderProtectionKey encrypts the 32-byte packet header. It is part of the
	// configuration, not a per-interface secret: every peer must have it, and
	// it must be persisted rather than regenerated, or every client stops
	// connecting.
	HeaderProtectionKey string

	// RandomTrailers pads every packet to a random size below the largest size
	// seen so far. Unlike the junk and signature packets this changes what the
	// receiver has to accept - it drops a packet whose size is not exactly the
	// expected one - so it has to be on at both ends.
	RandomTrailers bool

	// DisableCookies stops the interface from sending cookie replies at all,
	// removing one packet type from the fingerprint.
	DisableCookies bool

	// ContentPaddingAddition is a random per-packet padding range ("10-20").
	// It replaces the random-trailer amount for transport packets, and the
	// receiver still has to accept the larger packets, so it needs
	// RandomTrailers as well.
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
	boolean := func(v bool) string {
		if !v {
			return ""
		}
		return "1"
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
		{"random_trailers", boolean(a.RandomTrailers)},
		{"disable_cookies", boolean(a.DisableCookies)},
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

// Validate reports whether the device would accept these parameters, so that a
// caller can refuse a bad configuration at startup instead of at the first
// handshake. LoadConfig validates as well; this is for checking before an
// interface exists.
func (a AmneziaConfig) Validate() error {
	return a.validate()
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
		value *uint32
	}{{"s1", a.S1}, {"s2", a.S2}, {"s3", a.S3}, {"s4", a.S4}} {
		if field.value != nil && *field.value > maxPaddingSize {
			return fmt.Errorf("%s must not be larger than %d, the largest padding AmneziaWG accepts", field.name, maxPaddingSize)
		}
	}

	// These are uint32 ranges on the wire, for the device and for a client:
	// "1234" or "123-456". The syntax is the device's, without trimming, so
	// that a value which passes here is one the device will accept too.
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"h1", a.H1}, {"h2", a.H2}, {"h3", a.H3}, {"h4", a.H4},
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
		if strings.TrimSpace(*field.value) == "" {
			return fmt.Errorf("%s must not be empty", field.name)
		}
		if err := validateUintRange(field.name, *field.value); err != nil {
			return err
		}
	}

	// A signature packet is a small tag language the client parses with the
	// same code the device uses. Checking it here is what turns "the client
	// will not import this file" into a startup error.
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"i1", a.I1}, {"i2", a.I2}, {"i3", a.I3}, {"i4", a.I4}, {"i5", a.I5},
	} {
		if field.value == nil {
			continue
		}
		if strings.TrimSpace(*field.value) == "" {
			return fmt.Errorf("%s must not be empty", field.name)
		}
		if err := validateObfSpec(field.name, *field.value); err != nil {
			return err
		}
	}
	return nil
}

// validateUintRange accepts exactly what AmneziaWG's UintRange.FromString
// accepts: one 32-bit decimal number, or two separated by a single "-".
func validateUintRange(name, value string) error {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return fmt.Errorf("%s: %q is not a number or a range", name, value)
	}
	low, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return fmt.Errorf("%s: %q is not a number or a range", name, value)
	}
	if len(parts) == 2 {
		high, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("%s: %q is not a number or a range", name, value)
		}
		if high < low {
			return fmt.Errorf("%s: %q ends before it begins", name, value)
		}
	}
	return nil
}

// obfTagArg validates the argument of one signature-packet tag. The tag set is
// the one amneziawg-go's device/obf*.go implements at the pinned version; a tag
// added there has to be added here, or a profile the client accepts would be
// refused.
var obfTagArg = map[string]func(string) error{
	"b":  validateObfBytes,
	"t":  func(string) error { return nil },
	"r":  validateObfLength,
	"rc": validateObfLength,
	"rd": validateObfLength,
	"d":  func(string) error { return nil },
	"ds": func(string) error { return nil },
	"dz": validateObfLength,
}

// validateObfSpec checks one I1-I5 signature packet. Text outside the tags is
// ignored, the same way the device ignores it.
func validateObfSpec(name, spec string) error {
	tags := 0
	remaining := spec
	for {
		start := strings.IndexByte(remaining, '<')
		if start < 0 {
			break
		}
		end := strings.IndexByte(remaining[start:], '>')
		if end < 0 {
			return fmt.Errorf("%s: %q has a tag that is not closed with >", name, spec)
		}
		end += start

		parts := strings.Fields(remaining[start+1 : end])
		if len(parts) == 0 {
			return fmt.Errorf("%s: %q has an empty tag", name, spec)
		}
		check, ok := obfTagArg[parts[0]]
		if !ok {
			return fmt.Errorf(
				"%s: %q uses <%s>, which AmneziaWG does not know - it accepts b, t, r, rc, rd, d, ds and dz",
				name, spec, parts[0])
		}
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}
		if err := check(arg); err != nil {
			return fmt.Errorf("%s: <%s %s>: %w", name, parts[0], arg, err)
		}
		tags++
		remaining = remaining[end+1:]
	}

	if tags == 0 {
		return fmt.Errorf("%s: %q has no <...> tag, so it would send no packet at all", name, spec)
	}
	return nil
}

func validateObfBytes(arg string) error {
	value := strings.TrimPrefix(arg, "0x")
	if value == "" {
		return errors.New("needs a hexadecimal argument")
	}
	if len(value)%2 != 0 {
		return errors.New("has an odd number of hexadecimal digits")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return errors.New("is not hexadecimal")
	}
	return nil
}

func validateObfLength(arg string) error {
	length, err := strconv.Atoi(arg)
	if err != nil {
		return errors.New("needs a number")
	}
	if length < 0 {
		return errors.New("must not be negative")
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
