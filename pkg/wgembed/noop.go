package wgembed

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

type NoOpWireguardInterface struct{}

func NewNoOpInterface() WireGuardInterface                             { return &NoOpWireguardInterface{} }
func (*NoOpWireguardInterface) LoadConfig(*ConfigFile) error           { return nil }
func (*NoOpWireguardInterface) AddPeer(string, string, []string) error { return nil }
func (*NoOpWireguardInterface) ListPeers() ([]wgtypes.Peer, error)     { return []wgtypes.Peer{}, nil }
func (*NoOpWireguardInterface) RemovePeer(string) error                { return nil }
func (*NoOpWireguardInterface) PublicKey() (string, error)             { return "<publickey>", nil }
func (*NoOpWireguardInterface) Ping() error                            { return nil }
func (*NoOpWireguardInterface) Close() error                           { return nil }
