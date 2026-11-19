# amneziawg-embed

`wg-embed` with an AmneziaWG dataplane. It is a fork of
[`freifunkMUC/wg-embed`](https://github.com/freifunkMUC/wg-embed) and is
intended for use under
[`amnezia-wg-access-server`](https://github.com/sampletext32/wg-access-server).

The fork keeps everything `wg-embed` provides — the `WireGuardInterface` API,
config-file parsing, peer management through `wgctrl`, kernel route
synchronisation, the no-op implementation and the platform split — and replaces
the userspace WireGuard device with
[`amneziawg-go`](https://github.com/amnezia-vpn/amneziawg-go). The extra
AmneziaWG parameters (`Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4`, `I1`–`I5`,
header protection key, padding and timings) are set through
`IfaceConfig.Amnezia`.

Two consequences of that swap:

- **No kernel path.** AmneziaWG has no kernel module, and a kernel WireGuard
  interface would silently ignore every AmneziaWG parameter. `Options`
  `AllowKernelModule` is still accepted, so `wg-embed` callers compile
  unchanged, but it is ignored and the userspace implementation is always used.
- **The device is the AmneziaWG one**, so everything `wgctrl` configures (keys,
  listen port, peers, allowed IPs) goes through the same UAPI socket as before,
  and the AmneziaWG parameters are sent to the device directly, once, when the
  configuration is loaded.

See [`docs/architecture.md`](docs/architecture.md) and
[`docs/api-compatibility.md`](docs/api-compatibility.md).
