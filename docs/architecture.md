# Architecture

The package is `wg-embed`'s, with the userspace device implementation taken from
AmneziaWG.

- `iface.go` — `WireGuardInterface`, `Options`, `commonInterface` (the `wgctrl`
  client, the loaded config, the route bookkeeping).
- `config.go` — reading a wg-quick style file into `ConfigFile`/`IfaceConfig`.
  This fork adds `IfaceConfig.Amnezia`, which is never read from a file
  (`ini:"-"`): AmneziaWG parameters come from the caller.
- `iface_userspace.go` — TUN, AmneziaWG device, UAPI socket, and the
  `wgctrl` client that configures the device over that socket. This is the only
  file whose imports differ from upstream: `golang.zx2c4.com/wireguard/{conn,
  device,ipc,tun}` become `github.com/amnezia-vpn/amneziawg-go/v3/{...}`.
- `amnezia.go` — the `AmneziaConfig` type, its validation and its UAPI
  rendering. `LoadConfig` sends it to the device with `Device.IpcSet` after
  `wgctrl` has configured everything else; the device merges, so peers, keys and
  the listen port are untouched.
- `management.go` — peers, `PublicKey`, `Port`, `Ping`, all through `wgctrl`.
  Because the device is driven over the same UAPI socket, none of this needed to
  change, and public keys keep the base64 form callers expect.
- `routes*.go` — keeping the kernel routing table in line with the peers'
  allowed IPs (`Options.ManageRoutes`), unchanged from upstream.

On Linux there are two implementations behind the same interface:
`iface_kernel_linux.go` creates the AmneziaWG kernel module's device and
configures it through `awgnetlink` (the module's own generic-netlink family),
and `iface_userspace.go` drives the embedded `amneziawg-go` device over its UAPI
socket. `NewWithOpts` tries the kernel one first when
`Options.AllowKernelModule` is set and falls back to the userspace one when it
cannot be created. On a platform other than Linux the `wg-embed` platform files
still decide what exists; only the userspace device does.
