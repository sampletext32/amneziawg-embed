package awgspec

import "testing"

func TestParseUintRange(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		low     uint32
		high    uint32
		wantErr bool
	}{
		{name: "single number", value: "1234", low: 1234, high: 1234},
		{name: "range", value: "123-456", low: 123, high: 456},
		{name: "equal ends", value: "456-456", low: 456, high: 456},
		{name: "zero", value: "0-0", low: 0, high: 0},
		{name: "uint32 max", value: "4294967295", low: 4294967295, high: 4294967295},
		{name: "ends before it begins", value: "500-400", wantErr: true},
		{name: "too many parts", value: "1-2-3", wantErr: true},
		{name: "empty", value: "", wantErr: true},
		{name: "not a number", value: "ten", wantErr: true},
		{name: "negative", value: "-10", wantErr: true},
		{name: "overflows uint32", value: "4294967296", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			low, high, err := ParseUintRange("h1", test.value)
			if test.wantErr {
				if err == nil {
					t.Fatalf("%q was accepted as %d-%d", test.value, low, high)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if low != test.low || high != test.high {
				t.Fatalf("got %d-%d, want %d-%d", low, high, test.low, test.high)
			}
		})
	}
}
