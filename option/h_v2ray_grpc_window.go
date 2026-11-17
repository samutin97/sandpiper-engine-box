package option

// V2RayGRPCWindowOptions are the HTTP/2 receive windows of the gRPC transport's client (the full
// gRPC one, built with the with_grpc tag). 0 takes the default; see
// transport/v2raygrpc/h_window.go. //H
type V2RayGRPCWindowOptions struct {
	// InitialWindowSize is the receive window of each stream, in bytes: how much the server may
	// send on one connection before the client acknowledges it. 0 is 4 MiB (1 MiB in low-memory
	// mode); a negative value keeps gRPC's dynamic window, which starts at 64 KiB and grows with
	// its bandwidth estimate. Below 64 KiB it is 64 KiB.
	InitialWindowSize int32 `json:"initial_window_size,omitempty"`
	// InitialConnectionWindowSize is the receive window of the whole HTTP/2 connection, shared by
	// its streams. 0 is 16 MiB; never less than the stream window. Ignored with the dynamic window.
	InitialConnectionWindowSize int32 `json:"initial_connection_window_size,omitempty"`
}
