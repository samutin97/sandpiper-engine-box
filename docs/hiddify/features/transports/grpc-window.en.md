# gRPC receive windows

[فارسی](grpc-window.fa.md) · [All Hiddify features](../../index.md)

The client of the gRPC transport (`"type": "grpc"`, the full gRPC built with the `with_grpc` tag)
opens its HTTP/2 receive windows wide from the first byte: 4 MiB for each stream and 16 MiB for the
connection. gRPC itself starts at 64 KiB and grows the windows from a bandwidth estimate, so the
first download on every new connection crawled over a long round trip.

## Why use it

- The first download on a new connection runs at full speed. Over a 350 ms round trip the first
  2 MB took 3.7 s with gRPC's growing window and 0.53 s with a 4 MiB one; at 700 ms, 8.1 s against
  1.05 s.
- A new connection is common on a phone: at the start, after a network change, and each time the
  server (nginx closes an idle one after 75 s by default) drops the idle connection.
- gRPC's bandwidth pings stop, which some CDNs answer with a GOAWAY that closes the connection.

## How it gets past filtering

It does not change what the network sees beyond the window values in the HTTP/2 SETTINGS and
WINDOW_UPDATE frames, inside TLS. It only makes the transport faster.

## How it works

- gRPC opens a connection with HTTP/2's windows of 64 KiB and, from bandwidth-delay pings, grows them
  by about half every two round trips: 64 KiB, 128, 192, 320, 512, 800 KiB, 1.3 MiB. Until then a
  download gets one window per round trip. The grown window stays with the connection, which is why
  later downloads were fast and only the first one was slow.
- With a window set, the client says it in its first SETTINGS frame (stream window) and its first
  WINDOW_UPDATE (connection window), before the first request. A fixed window turns gRPC's estimate
  off: gRPC has no setting for a larger start that keeps growing.
- A stream whose reader stops holds at most its window of data: 4 MiB, less than the 16 MiB that
  gRPC's estimate may reach. In low-memory mode the stream window is 1 MiB. The connection window
  only limits the bytes in flight, since gRPC gives it back as data arrives.
- The same 4 MiB per stream is what Go's HTTP/2 client opens, which the XHTTP transport and the
  gRPC-lite client use. Xray's `initial_windows_size` sets such a fixed window for its gRPC client.
- The server side and the gRPC-lite client are unchanged.

## Configuration

```json
{
  "transport": {
    "type": "grpc",
    "service_name": "TunService",
    "initial_window_size": 4194304,
    "initial_connection_window_size": 16777216
  }
}
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `initial_window_size` | int (bytes) | `0`: 4 MiB, 1 MiB in low-memory mode | Receive window of each stream. Below 64 KiB it is 64 KiB. A negative value keeps gRPC's own window, which starts at 64 KiB and grows from its estimate (the behaviour before). |
| `initial_connection_window_size` | int (bytes) | `0`: 16 MiB | Receive window of the connection, shared by its streams; never less than the stream window. Ignored with a negative `initial_window_size`. |

## Notes

- A link without these fields gets the defaults: no change to links or to ray2sing is needed.
- Tested with `TestH_GRPCClientWindows` (the SETTINGS and WINDOW_UPDATE the client sends) and
  `TestH_GRPCFirstDownloadOverLongRoundTrip` (2 MB over a 200 ms round trip: 0.3 s with the
  defaults, 2.3 s with gRPC's own window).

## See also

- [Custom gRPC paths](grpc-custom-path.en.md)
- [XHTTP transport](xhttp.en.md)
- [Multiplex: Hiddify additions](multiplex-hiddify.en.md)
