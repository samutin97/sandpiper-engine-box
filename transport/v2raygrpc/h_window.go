package v2raygrpc

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"

	"google.golang.org/grpc"
)

// The client's HTTP/2 receive windows.
//
// gRPC starts a connection with windows of 64 KiB and grows them from its own bandwidth estimate
// (BDP pings), by about half every two round trips: 64 KiB, 128, 192, 320, 512, 800 KiB, 1.3 MiB.
// Until then a download gets one window per round trip, and every new connection (a start, a
// network change, a server that closed the idle one) starts over. Over a 350 ms round trip the
// first 2 MB on a new connection took 3.7 s, against 0.53 s with a 4 MiB window; at 700 ms, 8.1 s
// against 1.05 s. The next downloads on the same connection were fast. Go's HTTP/2 client, which
// XHTTP and gRPC-lite use, opens 4 MiB per stream from the start, and Xray's initial_windows_size
// sets such a fixed window for gRPC.
//
// A fixed window turns the estimate off: gRPC has no option for a larger start that keeps it. Its
// pings stop too, which some CDNs answer with a GOAWAY. A stream whose reader stops holds at most
// its window: 4 MiB, against the 16 MiB the estimate may reach; 1 MiB in low-memory mode. The
// connection window only limits the bytes in flight: gRPC gives it back as data arrives, read or
// not. //H
const (
	DefaultInitialWindowSize          = 4 << 20
	DefaultLowMemoryInitialWindowSize = 1 << 20
	DefaultInitialConnWindowSize      = 16 << 20
	minWindowSize                     = 65535 // HTTP/2's own; gRPC ignores less
)

// windowDialOptions gives the dial options of the receive windows; none for the dynamic window.
func windowDialOptions(options option.V2RayGRPCWindowOptions) []grpc.DialOption {
	stream, connection := options.InitialWindowSize, options.InitialConnectionWindowSize
	if stream < 0 {
		return nil
	}
	if stream == 0 {
		stream = DefaultInitialWindowSize
		if common.LowMemory {
			stream = DefaultLowMemoryInitialWindowSize
		}
	}
	stream = max(stream, minWindowSize)
	if connection <= 0 {
		connection = DefaultInitialConnWindowSize
	}
	connection = max(connection, stream)
	return []grpc.DialOption{grpc.WithInitialWindowSize(stream), grpc.WithInitialConnWindowSize(connection)}
}
