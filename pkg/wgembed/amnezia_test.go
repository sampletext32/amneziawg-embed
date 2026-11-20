package wgembed

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// amneziaTestKey is a valid 32-byte key in the base64 form a configuration
// carries; the UAPI form of the same key is its hex encoding.
func amneziaTestKey() (string, string) {
	raw := []byte("0123456789abcdef0123456789abcdef")
	return base64.StdEncoding.EncodeToString(raw), hex.EncodeToString(raw)
}

func uint32Ptr(v uint32) *uint32 { return &v }
func stringPtr(v string) *string { return &v }

func TestAmneziaConfigIsZero(t *testing.T) {
	if !(AmneziaConfig{}).IsZero() {
		t.Fatal("an empty configuration must report itself as zero")
	}
	if (AmneziaConfig{JC: uint32Ptr(0)}).IsZero() {
		t.Fatal("an explicitly set zero is still a set parameter")
	}
	key, _ := amneziaTestKey()
	if (AmneziaConfig{HeaderProtectionKey: key}).IsZero() {
		t.Fatal("a header protection key alone must not count as zero")
	}
	if (AmneziaConfig{RandomTrailers: true}).IsZero() {
		t.Fatal("random trailers alone must not count as zero")
	}
	if (AmneziaConfig{DisableCookies: true}).IsZero() {
		t.Fatal("disabled cookies alone must not count as zero")
	}
}

func TestAmneziaConfigValidate(t *testing.T) {
	key, _ := amneziaTestKey()

	tests := []struct {
		name    string
		config  AmneziaConfig
		wantErr string
	}{
		{
			name:   "plain values",
			config: AmneziaConfig{JC: uint32Ptr(4), JMin: uint32Ptr(500), JMax: uint32Ptr(1000), S1: uint32Ptr(8), H1: stringPtr("123456-123500")},
		},
		{
			name:    "jmin above jmax",
			config:  AmneziaConfig{JMin: uint32Ptr(2000), JMax: uint32Ptr(1000)},
			wantErr: "jmin must not be larger than jmax",
		},
		{
			name:    "empty range value",
			config:  AmneziaConfig{H2: stringPtr("  ")},
			wantErr: "h2 must not be empty",
		},
		{
			name:    "header protection key is not a key",
			config:  AmneziaConfig{HeaderProtectionKey: "not-a-key", S1: uint32Ptr(12)},
			wantErr: "header protection key is invalid",
		},
		{
			name:    "header protection with too small padding",
			config:  AmneziaConfig{HeaderProtectionKey: key, S4: uint32Ptr(8)},
			wantErr: "header protection needs s4 of at least 12",
		},
		{
			name:   "header protection with padding at the limit",
			config: AmneziaConfig{HeaderProtectionKey: key, S1: uint32Ptr(12), S4: uint32Ptr(12)},
		},
		{
			name:   "small padding without header protection",
			config: AmneziaConfig{S1: uint32Ptr(8), S4: uint32Ptr(8)},
		},
		{
			name:    "padding the device cannot parse",
			config:  AmneziaConfig{S1: uint32Ptr(65536)},
			wantErr: "s1 must not be larger than 65535",
		},
		{
			name:    "a header range that is not a range",
			config:  AmneziaConfig{H2: stringPtr("123-456-789")},
			wantErr: "h2",
		},
		{
			name:    "a header range that ends before it begins",
			config:  AmneziaConfig{H2: stringPtr("500-400")},
			wantErr: "ends before it begins",
		},
		{
			name:    "a padding range that is not a range",
			config:  AmneziaConfig{ContentPaddingAddition: stringPtr("ten-twenty")},
			wantErr: "content_padding_addition",
		},
		{
			name:    "a timing that is not a range",
			config:  AmneziaConfig{RekeyAfterTime: stringPtr("soon")},
			wantErr: "rekey_after_time",
		},
		{
			name:    "a signature packet with a tag the device does not know",
			config:  AmneziaConfig{I1: stringPtr("<b 0xf6ab3267fa><c><t>")},
			wantErr: "uses <c>",
		},
		{
			name:    "a signature packet with odd hex",
			config:  AmneziaConfig{I1: stringPtr("<b 0x123>")},
			wantErr: "odd number of hexadecimal digits",
		},
		{
			name:    "a signature packet with no tags at all",
			config:  AmneziaConfig{I1: stringPtr("hello")},
			wantErr: "no <...> tag",
		},
		{
			name:   "a signature packet the device accepts",
			config: AmneziaConfig{I1: stringPtr("<b 0xc00000000108><r 8><b 0x0000><r 900>")},
		},
		{
			name:   "an empty AmneziaWG section",
			config: AmneziaConfig{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.validate()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error %q does not contain %q", err, test.wantErr)
			}
		})
	}
}

func TestAmneziaConfigUAPIIsStableAndComplete(t *testing.T) {
	key, keyHex := amneziaTestKey()

	config := AmneziaConfig{
		JC:                     uint32Ptr(4),
		JMin:                   uint32Ptr(500),
		JMax:                   uint32Ptr(1000),
		S1:                     uint32Ptr(12),
		S2:                     uint32Ptr(13),
		S3:                     uint32Ptr(14),
		S4:                     uint32Ptr(15),
		H1:                     stringPtr("123456-123500"),
		I1:                     stringPtr("<b 0xf6ab3267fa><r 8><t>"),
		HeaderProtectionKey:    key,
		RandomTrailers:         true,
		DisableCookies:         true,
		ContentPaddingAddition: stringPtr("10-20"),
		MaxHandshakeAttempts:   stringPtr("5"),
	}

	got, err := config.uapi()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := strings.Join([]string{
		"jc=4",
		"jmin=500",
		"jmax=1000",
		"s1=12",
		"s2=13",
		"s3=14",
		"s4=15",
		"h1=123456-123500",
		"i1=<b 0xf6ab3267fa><r 8><t>",
		"content_padding_addition=10-20",
		"random_trailers=1",
		"disable_cookies=1",
		"max_handshake_attempts=5",
		"header_protection_key=" + keyHex,
	}, "\n") + "\n\n" // the blank line that ends the UAPI set operation
	if got != want {
		t.Fatalf("unexpected UAPI body:\n got: %q\nwant: %q", got, want)
	}
}

func TestAmneziaConfigUAPIOmitsUnsetAndSendsExplicitZero(t *testing.T) {
	got, err := AmneziaConfig{JC: uint32Ptr(0)}.uapi()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "jc=0\n\n" {
		t.Fatalf("an explicit zero must be sent, unset values must not: %q", got)
	}

	empty, err := (AmneziaConfig{}).uapi()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if empty != "" {
		t.Fatalf("an empty configuration must render nothing, got %q", empty)
	}
}

func TestAmneziaConfigUAPIRejectsInvalidValues(t *testing.T) {
	if _, err := (AmneziaConfig{JMin: uint32Ptr(10), JMax: uint32Ptr(5)}).uapi(); err == nil {
		t.Fatal("expected the invalid range to be rejected")
	}
}
