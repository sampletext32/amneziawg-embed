package wgembed

import (
	"encoding/hex"
	"errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"strconv"
	"strings"
	"time"
)

func renderConfig(c *ConfigFile) string {
	var b strings.Builder
	put := func(k, v string) {
		if v != "" {
			b.WriteString(k + "=" + v + "\n")
		}
	}
	if c.Interface.PrivateKey != "" {
		k, _ := wgtypes.ParseKey(c.Interface.PrivateKey)
		put("private_key", hex.EncodeToString(k[:]))
	}
	if c.Interface.ListenPort != nil {
		put("listen_port", strconv.Itoa(*c.Interface.ListenPort))
	}
	a := c.Interface.Amnezia
	for k, v := range map[string]*uint32{"jc": a.JC, "jmin": a.JMin, "jmax": a.JMax, "s1": a.S1, "s2": a.S2, "s3": a.S3, "s4": a.S4} {
		put(k, u32(v))
	}
	for k, v := range map[string]*string{"h1": a.H1, "h2": a.H2, "h3": a.H3, "h4": a.H4, "i1": a.I1, "i2": a.I2, "i3": a.I3, "i4": a.I4, "i5": a.I5, "content_padding_addition": a.ContentPaddingAddition, "rekey_after_time": a.RekeyAfterTime, "rekey_timeout": a.RekeyTimeout, "reject_after_time": a.RejectAfterTime, "keepalive_timeout": a.KeepaliveTimeout, "max_handshake_attempts": a.MaxHandshakeAttempts} {
		if v != nil {
			put(k, *v)
		}
	}
	if a.HeaderProtectionKey != "" {
		k, _ := wgtypes.ParseKey(a.HeaderProtectionKey)
		put("header_protection_key", hex.EncodeToString(k[:]))
	}
	for _, p := range c.Peers {
		k, _ := wgtypes.ParseKey(p.PublicKey)
		put("public_key", hex.EncodeToString(k[:]))
		for _, ip := range p.AllowedIPs {
			put("allowed_ip", ip)
		}
	}
	b.WriteString("\n")
	return b.String()
}

func parsePeers(raw string) ([]wgtypes.Peer, error) {
	var out []wgtypes.Peer
	var p *wgtypes.Peer
	flush := func() {
		if p != nil {
			out = append(out, *p)
			p = nil
		}
	}
	for _, line := range strings.Split(raw, "\n") {
		if line == "" {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := kv[0], kv[1]
		if k == "errno" {
			if v != "0" {
				return nil, errors.New("device returned errno " + v)
			}
			continue
		}
		if k == "public_key" {
			flush()
			key, err := wgtypes.ParseKey(hexToB64(v))
			if err != nil {
				return nil, err
			}
			p = &wgtypes.Peer{PublicKey: key}
			continue
		}
		if p == nil {
			continue
		}
		switch k {
		case "preshared_key":
			key, err := wgtypes.ParseKey(hexToB64(v))
			if err == nil {
				p.PresharedKey = key
			}
		case "endpoint":
			a, err := net.ResolveUDPAddr("udp", v)
			if err == nil {
				p.Endpoint = a
			}
		case "allowed_ip":
			_, n, err := net.ParseCIDR(v)
			if err == nil {
				p.AllowedIPs = append(p.AllowedIPs, *n)
			}
		case "persistent_keepalive_interval":
			n, err := strconv.ParseUint(v, 10, 16)
			if err == nil {
				p.PersistentKeepaliveInterval = time.Duration(n) * time.Second
			}
		case "last_handshake_time_sec":
			n, err := strconv.ParseInt(v, 10, 64)
			if err == nil {
				p.LastHandshakeTime = time.Unix(n, int64(p.LastHandshakeTime.Nanosecond()))
			}
		case "last_handshake_time_nsec":
			n, err := strconv.ParseInt(v, 10, 64)
			if err == nil {
				p.LastHandshakeTime = time.Unix(p.LastHandshakeTime.Unix(), n)
			}
		case "rx_bytes":
			n, err := strconv.ParseInt(v, 10, 64)
			if err == nil {
				p.ReceiveBytes = n
			}
		case "tx_bytes":
			n, err := strconv.ParseInt(v, 10, 64)
			if err == nil {
				p.TransmitBytes = n
			}
		}
	}
	flush()
	return out, nil
}
func hexToB64(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return ""
	}
	k, err := wgtypes.NewKey(b)
	if err != nil {
		return ""
	}
	return k.String()
}
