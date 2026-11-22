# amneziawg-embed

`wg-embed` with an AmneziaWG dataplane. It is a fork of
[`freifunkMUC/wg-embed`](https://github.com/freifunkMUC/wg-embed) and is
intended for use under
[`amnezia-wg-access-server`](https://github.com/sampletext32/wg-access-server).

The fork keeps everything `wg-embed` provides — the `WireGuardInterface` API,
config-file parsing, peer management through `wgctrl`, kernel route
synchronisation, the no-op implementation and the platform split — and replaces
the WireGuard device with AmneziaWG's: on Linux the node's `amneziawg` kernel
module when it is usable, otherwise the embedded
[`amneziawg-go`](https://github.com/amnezia-vpn/amneziawg-go) device. The extra
AmneziaWG parameters (`Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4`, `I1`–`I5`,
header protection key, random trailers, disabled cookies, content padding and
the timings) are set through `IfaceConfig.Amnezia`.

Two consequences of that swap:

- **Kernel module first, userspace as the fallback.** On Linux,
  `Options.AllowKernelModule` asks for the AmneziaWG kernel module's own device:
  a real rtnl link of type `amneziawg`, configured through the module's
  generic-netlink family. When the module cannot be used — not installed, not
  loaded on the node, older than netlink family version 3, or the link cannot be
  created — the embedded `amneziawg-go` device is used instead. Both speak the
  same protocol, so the fallback changes where packets are processed, not
  compatibility; the chosen dataplane is logged at startup.
- **The device is the AmneziaWG one**, so everything `wgctrl` configures (keys,
  listen port, peers, allowed IPs) keeps working, and the AmneziaWG parameters
  are sent to the device once, when the configuration is loaded — over the UAPI
  socket for the userspace device, as extra netlink attributes for the kernel
  device.

Built against
[`github.com/amnezia-vpn/amneziawg-go/v3`](https://github.com/amnezia-vpn/amneziawg-go)
`v3.1.20261116`; see [`go.mod`](go.mod). The kernel dataplane exists only on
Linux and needs the node's `amneziawg-dkms` module; elsewhere the package still
builds with the userspace device, and setting `IfaceConfig.Amnezia` on a platform
without a device handle is an error rather than a silent downgrade to plain
WireGuard.

See [`docs/architecture.md`](docs/architecture.md) and
[`docs/api-compatibility.md`](docs/api-compatibility.md).

## Branches

- **`amnezia`** — this fork's work: `wg-embed` master plus the AmneziaWG
  dataplane. All changes live here.
- **`master`** — an exact mirror of
  [`freifunkMUC/wg-embed`](https://github.com/freifunkMUC/wg-embed). It carries
  nothing of this fork, not even its module path, and is never pushed to by
  hand.

Keeping them apart means `master` can be fast-forwarded to upstream at any
time, and the AmneziaWG delta stays a single rebasable series:

```sh
git fetch upstream
git switch amnezia
git rebase upstream/master
```

Depend on the **`amnezia` branch or a tag**, never on `master`: the module path
here is `github.com/sampletext32/amneziawg-embed`, while `master` still declares
`github.com/freifunkMUC/wg-embed`.

