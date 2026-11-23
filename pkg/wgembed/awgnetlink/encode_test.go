//go:build linux

package awgnetlink

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func strptr(v string) *string { return &v }
func u32ptr(v uint32) *uint32 { return &v }

// The v3 attribute carries a keepalive interval as one 16-bit range packed into
// a u32, even when it is a single number. Getting the halves swapped would be a
// silently wrong keepalive.
func TestPackedSeconds(t *testing.T) {
	tests := []struct {
		interval time.Duration
		want     uint32
		wantErr  bool
	}{
		{interval: 0, want: 0},
		{interval: 25 * time.Second, want: 25 | 25<<16},
		{interval: 65535 * time.Second, want: 65535 | 65535<<16},
		{interval: -time.Second, wantErr: true},
		{interval: 65536 * time.Second, wantErr: true},
	}

	for _, test := range tests {
		got, err := packedSeconds(test.interval)
		if test.wantErr {
			if err == nil {
				t.Errorf("%s was accepted as %d", test.interval, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", test.interval, err)
			continue
		}
		if got != test.want {
			t.Errorf("%s: packed 0x%08x, want 0x%08x", test.interval, got, test.want)
		}
	}
}

// The kernel's policy expects a raw sockaddr: family in host byte order, port
// in network byte order, address at the offset the C struct has it.
func TestEncodeSockaddrIPv4(t *testing.T) {
	b, err := encodeSockaddr(&net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4700})()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 16 {
		t.Fatalf("sockaddr_in is %d bytes, want 16", len(b))
	}
	if family := binary.LittleEndian.Uint16(b[0:2]); family != unix.AF_INET {
		t.Errorf("family = %d, want AF_INET", family)
	}
	if port := binary.BigEndian.Uint16(b[2:4]); port != 4700 {
		t.Errorf("port = %d, want 4700", port)
	}
	if ip := net.IP(b[4:8]); !ip.Equal(net.ParseIP("203.0.113.7")) {
		t.Errorf("address = %v", ip)
	}
}

func TestEncodeSockaddrIPv6(t *testing.T) {
	b, err := encodeSockaddr(&net.UDPAddr{IP: net.ParseIP("2001:db8::7"), Port: 4701})()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 28 {
		t.Fatalf("sockaddr_in6 is %d bytes, want 28", len(b))
	}
	if family := binary.LittleEndian.Uint16(b[0:2]); family != unix.AF_INET6 {
		t.Errorf("family = %d, want AF_INET6", family)
	}
	if port := binary.BigEndian.Uint16(b[2:4]); port != 4701 {
		t.Errorf("port = %d, want 4701", port)
	}
	if ip := net.IP(b[8:24]); !ip.Equal(net.ParseIP("2001:db8::7")) {
		t.Errorf("address = %v", ip)
	}
}

// encodeAmnezia is the wire contract with the module: the attribute numbers and
// the packing. A wrong number is a parameter the device never receives.
func TestEncodeAmneziaAttributes(t *testing.T) {
	enc := netlink.NewAttributeEncoder()
	err := encodeAmnezia(enc, AmneziaConfig{
		S1:                     u32ptr(12),
		H1:                     strptr("100-200"),
		I1:                     strptr("<b 0x0000>"),
		ContentPaddingAddition: strptr("10-20"),
		RandomTrailers:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := enc.Encode()
	if err != nil {
		t.Fatal(err)
	}

	ad, err := netlink.NewAttributeDecoder(attrs)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint16]bool{}
	for ad.Next() {
		seen[ad.Type()] = true
		switch ad.Type() {
		case wgdeviceAS1:
			if got := ad.Uint16(); got != 12 {
				t.Errorf("s1 = %d, want 12", got)
			}
		case wgdeviceAH1:
			// low in the low 32 bits, high in the high 32
			if got := ad.Uint64(); got != uint64(100)|uint64(200)<<32 {
				t.Errorf("h1 = 0x%016x", got)
			}
		case wgdeviceAContentPaddingAddition:
			if got := ad.Uint32(); got != uint32(10)|uint32(20)<<16 {
				t.Errorf("content padding = 0x%08x", got)
			}
		case wgdeviceAI1:
			if got := ad.String(); got != "<b 0x0000>" {
				t.Errorf("i1 = %q", got)
			}
		case wgdeviceARandomTrailers:
			if got := ad.Uint8(); got != 1 {
				t.Errorf("random trailers = %d, want 1", got)
			}
		}
	}
	if err := ad.Err(); err != nil {
		t.Fatal(err)
	}

	for _, attr := range []uint16{wgdeviceAS1, wgdeviceAH1, wgdeviceAI1, wgdeviceAContentPaddingAddition, wgdeviceARandomTrailers} {
		if !seen[attr] {
			t.Errorf("attribute %d was not encoded", attr)
		}
	}
}
