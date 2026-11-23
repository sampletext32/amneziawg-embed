// Package awgspec holds the AmneziaWG parameter rules that have to be the same
// whichever dataplane applies them.
//
// The kernel module and the embedded userspace device are two implementations
// of one protocol. A value one accepts and the other refuses is a profile that
// works on one node and not on the next, so the limits and the syntax live here
// once and both read them.
package awgspec

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// HeaderCipherNonceSize is the number of leading bytes AmneziaWG's header
	// cipher takes as its nonce. Padding smaller than this would encrypt real
	// header bytes, so a header protection key requires S1-S4 of at least this.
	HeaderCipherNonceSize = 12

	// MaxUint16 is the largest value a 16-bit attribute or half of a packed
	// range can carry.
	MaxUint16 = 65535

	// MaxPaddingSize is the largest S1-S4, for the same reason: both
	// implementations parse them as 16-bit values.
	MaxPaddingSize = MaxUint16

	// MaxPackedRangeValue is the largest value of an attribute that is a
	// 16-bit range packed into one 32-bit word (content padding and the
	// timers): each half is 16 bits wide.
	MaxPackedRangeValue = MaxUint16
)

// ParseUintRange parses an AmneziaWG uint32 range: one decimal number, or two
// separated by a single "-". It accepts exactly what both implementations
// accept, so a value that passes here is one they take too.
func ParseUintRange(name, value string) (low, high uint32, err error) {
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
