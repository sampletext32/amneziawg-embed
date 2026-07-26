# API compatibility

The access server uses `WireGuardInterface`, `Options`, `NewNoOpInterface`,
`NewWithOpts`, `ConfigFile`, `IfaceConfig`, `LoadConfig`, `AddPeer`,
`RemovePeer`, `ListPeers`, `PublicKey`, `Ping`, and `Close` from `wg-embed`.

This module preserves those names and method signatures. `wgtypes.Peer` and
`wgtypes.Key` remain DTOs so the access server's device synchronization code
does not require a broad rewrite. `AllowKernelModule` remains in `Options` for
source compatibility but is ignored: this adapter has no kernel WireGuard or
standard wireguard-go path.
