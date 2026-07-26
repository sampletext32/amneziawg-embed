# Architecture

On Linux, `NewWithOpts` creates a TUN with `tun.CreateTUN`, a bind with
`conn.NewDefaultBind`, and an in-process `device.Device`. Configuration and
runtime status use direct `Device.IpcSet` and `Device.IpcGet` calls. Linux
netlink assigns addresses, sets MTU, and raises the link. `Close` owns device,
TUN, bind, and link cleanup.

`wgtypes` is retained only as a public data-transfer dependency for compatibility
with `wg-access-server`; no `wgctrl.Client` is constructed and no kernel or
standard WireGuard implementation is imported.
