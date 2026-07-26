# amneziawg-embed

This fork is based on [`freifunkMUC/wg-embed`](https://github.com/freifunkMUC/wg-embed)
and is intended for use under
[`amnezia-wg-access-server`](https://github.com/sampletext32/wg-access-server).

It provides an in-process AmneziaWG adapter for the narrow `wg-embed` API used
by the access server. The Linux implementation creates a TUN and AmneziaWG
device directly and calls `Device.IpcSet`/`Device.IpcGet`; it does not spawn a
daemon or use a UAPI socket.
