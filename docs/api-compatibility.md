# API compatibility

The fork tracks `wg-embed` master: every exported name and signature is the
upstream one, so a caller that builds against `wg-embed` builds against this
module by changing the import path only.

Additions:

- `IfaceConfig.Amnezia AmneziaConfig` — the AmneziaWG parameters of the
  interface, not read from a config file.
- `AmneziaConfig` — `JC/JMin/JMax`, `S1`–`S4`, `H1`–`H4`, `I1`–`I5`,
  `HeaderProtectionKey`, `RandomTrailers`, `DisableCookies`,
  `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`,
  `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`. Pointers keep
  "unset" distinct from zero, and `AmneziaConfig.IsZero()` reports an interface
  that therefore behaves as plain WireGuard.
- `AmneziaConfig` is validated when the configuration is loaded: `jmin <= jmax`,
  `S1`–`S4` within what the device parses (0–65535), every range value in the
  form the device accepts (`1234` or `123-456`), every `I1`–`I5` signature packet
  in the tag language the client parses, a parseable header protection key, and
  `S1`–`S4` of at least 12 whenever header protection is used (the header cipher
  takes a 12-byte nonce from the start of the packet).

Behaviour differences:

- `Options.AllowKernelModule` now means what it means upstream: try the kernel
  device first and fall back to the userspace one when it cannot be created.
  The device is the AmneziaWG module's (`type amneziawg`, netlink family
  `amneziawg`, version >= 3), not the stock kernel WireGuard interface. The
  fallback is logged, and only happens at creation time.
- Setting `IfaceConfig.Amnezia` on an interface implementation without a device
  handle is an error, never a silent no-op.

Everything else — `Options`, `ConfigFile`, `PeerConfig`, `ReadConfig`,
`NewKeyPair`, `ErrInterfaceExists`, `ErrUnsupportedPlatform`,
`NewNoOpInterface`, `WireGuardInterface`, `LoadConfig`, `AddPeer`,
`RemovePeer`, `ListPeers`, `PublicKey`, `Port`, `Ping`, `Close`, and the
`ManageRoutes` behaviour — is `wg-embed`'s.
