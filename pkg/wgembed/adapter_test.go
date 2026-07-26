package wgembed

import (
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestValidateAWG(t *testing.T) {
	lo, hi := uint32(8), uint32(4)
	if err := validateAWG(AmneziaConfig{JMin: &lo, JMax: &hi}); err == nil || !strings.Contains(err.Error(), "jmin") {
		t.Fatalf("expected field-specific range error, got %v", err)
	}
	if err := validateAWG(AmneziaConfig{H1: func() *string { v := ""; return &v }()}); err == nil || !strings.Contains(err.Error(), "h1") {
		t.Fatalf("expected field-specific empty-value error, got %v", err)
	}
}

func TestRenderConfigRedactsNothingIntoLogsAndUsesHexUAPI(t *testing.T) {
	k := wgtypes.Key{1}
	config := &ConfigFile{Interface: IfaceConfig{PrivateKey: k.String(), ListenPort: func() *int { v := 51920; return &v }(), Amnezia: AmneziaConfig{S1: func() *uint32 { v := uint32(8); return &v }()}}, Peers: []PeerConfig{{PublicKey: k.String(), AllowedIPs: []string{"10.0.0.2/32"}}}}
	rendered := renderConfig(config)
	if !strings.Contains(rendered, "private_key=010000") || !strings.Contains(rendered, "s1=8") || !strings.Contains(rendered, "allowed_ip=10.0.0.2/32") {
		t.Fatalf("unexpected UAPI rendering: %q", rendered)
	}
}

func TestParsePeers(t *testing.T) {
	k := wgtypes.Key{2}
	raw := "public_key=" + hexKey(k) + "\nendpoint=192.0.2.1:51820\nlast_handshake_time_sec=10\nlast_handshake_time_nsec=20\nrx_bytes=4\ntx_bytes=3\npersistent_keepalive_interval=25\nallowed_ip=10.0.0.2/32\nerrno=0\n\n"
	peers, err := parsePeers(raw)
	if err != nil || len(peers) != 1 || peers[0].ReceiveBytes != 4 || len(peers[0].AllowedIPs) != 1 || peers[0].PersistentKeepaliveInterval != 25*time.Second {
		t.Fatalf("unexpected parsed peer: %#v, %v", peers, err)
	}
}

func hexKey(k wgtypes.Key) string {
	var b strings.Builder
	const hex = "0123456789abcdef"
	for _, x := range k {
		b.WriteByte(hex[x>>4])
		b.WriteByte(hex[x&15])
	}
	return b.String()
}

func TestNoOp(t *testing.T) {
	wg := NewNoOpInterface()
	if err := wg.Ping(); err != nil {
		t.Fatal(err)
	}
	if got, err := wg.PublicKey(); err != nil || got != "<publickey>" {
		t.Fatalf("%q, %v", got, err)
	}
	if err := wg.Close(); err != nil {
		t.Fatal(err)
	}
}
