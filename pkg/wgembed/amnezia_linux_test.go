//go:build linux

package wgembed

import (
	"strings"
	"testing"
)

// TestAmneziaParametersReachTheDevice is the end-to-end check that the
// parameters actually arrive: it creates a real interface, loads a
// configuration with every family of parameter set, and reads the device back
// over UAPI. It needs CAP_NET_ADMIN and /dev/net/tun, like the other interface
// tests, and skips itself without WGEMBED_TEST_NETADMIN.
func TestAmneziaParametersReachTheDevice(t *testing.T) {
	requireNetAdmin(t)

	name := testInterfaceName(t)
	wg, err := NewWithOpts(Options{InterfaceName: name})
	if err != nil {
		t.Fatalf("creating the interface: %v", err)
	}
	t.Cleanup(func() { _ = wg.Close() })

	key, keyHex := amneziaTestKey()
	config := &ConfigFile{
		Interface: IfaceConfig{
			PrivateKey: key,
			Address:    []string{"10.199.0.1/24"},
			Amnezia: AmneziaConfig{
				JC:                     uint32Ptr(4),
				JMin:                   uint32Ptr(500),
				JMax:                   uint32Ptr(1000),
				S1:                     uint32Ptr(12),
				S2:                     uint32Ptr(13),
				S3:                     uint32Ptr(14),
				S4:                     uint32Ptr(15),
				H1:                     stringPtr("123456-123500"),
				I1:                     stringPtr("<b 0xfee1dead><r 8>"),
				HeaderProtectionKey:    key,
				RandomTrailers:         true,
				DisableCookies:         true,
				ContentPaddingAddition: stringPtr("10-20"),
			},
		},
	}
	if err := wg.LoadConfig(config); err != nil {
		t.Fatalf("loading the configuration: %v", err)
	}

	implementation, ok := wg.(*userspaceInterface)
	if !ok {
		t.Fatalf("expected the userspace implementation, got %T", wg)
	}
	raw, err := implementation.device.IpcGet()
	if err != nil {
		t.Fatalf("reading the device back: %v", err)
	}

	for _, want := range []string{
		"jc=4",
		"jmin=500",
		"jmax=1000",
		"s1=12",
		"s2=13",
		"s3=14",
		"s4=15",
		"h1=123456-123500",
		"i1=<b 0xfee1dead><r 8>",
		"header_protection_key=" + keyHex,
		"random_trailers=1",
		"disable_cookies=1",
		"content_padding_addition=10-20",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("the device does not report %q; it reports:\n%s", want, raw)
		}
	}
}
