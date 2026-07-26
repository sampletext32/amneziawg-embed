//go:build linux

package wgembed

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type embedded struct {
	mu     sync.Mutex
	name   string
	tun    tun.Device
	dev    *device.Device
	closed bool
}

func NewWithOpts(o Options) (WireGuardInterface, error) {
	if o.InterfaceName == "" {
		return nil, errors.New("interface name is required")
	}
	t, err := tun.CreateTUN(o.InterfaceName, device.DefaultMTU)
	if err != nil {
		return nil, err
	}
	d := device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "("+o.InterfaceName+") "))
	logrus.Debugf("amneziawg interface %s created", o.InterfaceName)
	return &embedded{name: o.InterfaceName, tun: t, dev: d}, nil
}

func (e *embedded) LoadConfig(c *ConfigFile) error {
	if err := c.validate(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("interface is closed")
	}
	if err := e.dev.IpcSet(renderConfig(c)); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}
	link, err := netlink.LinkByName(e.name)
	if err != nil {
		return err
	}
	for _, a := range c.Interface.Address {
		x, err := netlink.ParseAddr(a)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, x); err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
			return err
		}
	}
	mtu := device.DefaultMTU
	if c.Interface.MTU != nil {
		mtu = *c.Interface.MTU
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	logrus.Debug("amneziawg device configured")
	return nil
}
func (e *embedded) AddPeer(pk, psk string, ips []string) error {
	k, err := wgtypes.ParseKey(pk)
	if err != nil {
		return errors.New("peer public key is invalid")
	}
	var p *wgtypes.Key
	if psk != "" {
		x, er := wgtypes.ParseKey(psk)
		if er != nil {
			return errors.New("peer preshared key is invalid")
		}
		p = &x
	}
	var b strings.Builder
	b.WriteString("public_key=" + hex.EncodeToString(k[:]) + "\n")
	if p != nil {
		b.WriteString("preshared_key=" + hex.EncodeToString(p[:]) + "\n")
	}
	b.WriteString("replace_allowed_ips=true\n")
	for _, ip := range ips {
		if _, _, er := net.ParseCIDR(ip); er != nil {
			return er
		}
		b.WriteString("allowed_ip=" + ip + "\n")
	}
	b.WriteString("\n")
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("interface is closed")
	}
	return e.dev.IpcSet(b.String())
}
func (e *embedded) RemovePeer(pk string) error {
	k, err := wgtypes.ParseKey(pk)
	if err != nil {
		return errors.New("peer public key is invalid")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	return e.dev.IpcSet("public_key=" + hex.EncodeToString(k[:]) + "\nremove=true\n\n")
}
func (e *embedded) ListPeers() ([]wgtypes.Peer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, errors.New("interface is closed")
	}
	raw, err := e.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return parsePeers(raw)
}
func (e *embedded) PublicKey() (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return "", errors.New("interface is closed")
	}
	raw, err := e.dev.IpcGet()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "private_key=") {
			v, er := hex.DecodeString(strings.TrimPrefix(line, "private_key="))
			if er != nil || len(v) != 32 {
				return "", errors.New("invalid private key from device")
			}
			var in, out [32]byte
			copy(in[:], v)
			p, er := curve25519.X25519(in[:], curve25519.Basepoint)
			if er != nil {
				return "", er
			}
			copy(out[:], p)
			return hex.EncodeToString(out[:]), nil
		}
	}
	return "", errors.New("device private key is not configured")
}
func (e *embedded) Ping() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("interface is closed")
	}
	raw, err := e.dev.IpcGet()
	if err != nil {
		return err
	}
	_, err = parsePeers(raw)
	return err
}
func (e *embedded) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()
	e.dev.Close()
	if l, err := netlink.LinkByName(e.name); err == nil {
		_ = netlink.LinkDel(l)
	}
	return nil
}
