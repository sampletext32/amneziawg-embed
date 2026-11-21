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
header protection key, random trailers, disabled cookies, content padding and
the timings) are set through `IfaceConfig.Amnezia`.

Two consequences of that swap:

- **Userspace only, for now.** AmneziaWG does have a Linux kernel module
  (`amneziawg-dkms`, netlink family `amneziawg`), but this package has no
  backend for it yet. The kernel path it inherited from `wg-embed` creates a
  stock WireGuard interface, which would silently ignore every AmneziaWG
  parameter, so that path is not taken. `Options.AllowKernelModule` is still
  accepted, so `wg-embed` callers compile unchanged, but it is ignored and the
  userspace implementation is always used. A kernel backend is planned; see
  the workspace's `PLAN-kernel-module.md`.
- **The device is the AmneziaWG one**, so everything `wgctrl` configures (keys,
  listen port, peers, allowed IPs) goes through the same UAPI socket as before,
  and the AmneziaWG parameters are sent to the device directly, once, when the
  configuration is loaded.

Built against
[`github.com/amnezia-vpn/amneziawg-go/v3`](https://github.com/amnezia-vpn/amneziawg-go)
`v3.1.20261116`; see [`go.mod`](go.mod). AmneziaWG has both a kernel module and
a userspace implementation; this package currently only embeds the userspace
one, so Linux is the supported platform — on other platforms the package still
builds, but setting `IfaceConfig.Amnezia` there is an error rather than a silent
downgrade to plain WireGuard.

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

