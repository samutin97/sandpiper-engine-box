package v2raygrpc

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// hSender answers a 4-byte size with that many bytes, as a server relays a download.
type hSender struct{}

func (hSender) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer func() {
		conn.Close()
		onClose(nil)
	}()
	var sizeBuf [4]byte
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		return
	}
	chunk := make([]byte, 32<<10)
	for size := int(binary.BigEndian.Uint32(sizeBuf[:])); size > 0; {
		n := min(size, len(chunk))
		if _, err := conn.Write(chunk[:n]); err != nil {
			return
		}
		size -= n
	}
	io.Copy(io.Discard, conn)
}

func hStartSender(t *testing.T) M.Socksaddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server, err := NewServer(context.Background(), logger.NOP(), option.V2RayGRPCOptions{ServiceName: "tun"}, nil, hSender{})
	require.NoError(t, err)
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return M.SocksaddrFromNet(listener.Addr())
}

func hDownload(t *testing.T, client *Client, size int) time.Duration {
	t.Helper()
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	defer conn.Close()
	var sizeBuf [4]byte
	binary.BigEndian.PutUint32(sizeBuf[:], uint32(size))
	_, err = conn.Write(sizeBuf[:])
	require.NoError(t, err)
	n, err := io.CopyN(io.Discard, conn, int64(size))
	require.NoError(t, err)
	require.EqualValues(t, size, n)
	return time.Since(started)
}

type hDelayChunk struct {
	at   time.Time
	data []byte
}

// hDelayConn holds every byte for delay in each direction, so a round trip takes twice delay; its
// bandwidth is that of loopback.
type hDelayConn struct {
	net.Conn
	delay   time.Duration
	reads   chan hDelayChunk
	writes  chan hDelayChunk
	pending []byte
	done    chan struct{}
	once    sync.Once
}

func hNewDelayConn(conn net.Conn, delay time.Duration) *hDelayConn {
	c := &hDelayConn{Conn: conn, delay: delay, reads: make(chan hDelayChunk, 4096), writes: make(chan hDelayChunk, 4096), done: make(chan struct{})}
	go func() {
		defer close(c.reads)
		for {
			buf := make([]byte, 16<<10)
			n, err := c.Conn.Read(buf)
			if n > 0 {
				c.reads <- hDelayChunk{time.Now().Add(c.delay), buf[:n]}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case <-c.done:
				return
			case chunk := <-c.writes:
				time.Sleep(time.Until(chunk.at))
				if _, err := c.Conn.Write(chunk.data); err != nil {
					return
				}
			}
		}
	}()
	return c
}

func (c *hDelayConn) Read(b []byte) (int, error) {
	if len(c.pending) == 0 {
		chunk, ok := <-c.reads
		if !ok {
			return 0, io.EOF
		}
		time.Sleep(time.Until(chunk.at))
		c.pending = chunk.data
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *hDelayConn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	case c.writes <- hDelayChunk{time.Now().Add(c.delay), append([]byte(nil), b...)}:
		return len(b), nil
	}
}

func (c *hDelayConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// hFrameConn passes the client's bytes on and parses them as HTTP/2 frames.
type hFrameConn struct {
	net.Conn
	pipe *io.PipeWriter
}

func (c *hFrameConn) Write(b []byte) (int, error) {
	c.pipe.Write(b)
	return c.Conn.Write(b)
}

func (c *hFrameConn) Close() error {
	c.pipe.Close()
	return c.Conn.Close()
}

type hDialer struct {
	wrap func(net.Conn) net.Conn
}

func (d hDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := N.SystemDialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return d.wrap(conn), nil
}

func (d hDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// hPreface is what the client says of its windows before its first request: the stream window it
// sets (0 if it keeps HTTP/2's 65535) and how far it opens the connection window.
type hPreface struct {
	streamWindow     uint32
	connectionWindow uint32
}

func hClientPreface(t *testing.T, options option.V2RayGRPCWindowOptions) hPreface {
	t.Helper()
	serverAddr := hStartSender(t)
	reader, writer := io.Pipe()
	prefaceDone := make(chan hPreface, 1)
	go func() {
		defer reader.Close()
		var preface hPreface
		preface.connectionWindow = 65535
		if _, err := io.ReadFull(reader, make([]byte, len(http2.ClientPreface))); err != nil {
			return
		}
		framer := http2.NewFramer(nil, reader)
		for {
			frame, err := framer.ReadFrame()
			if err != nil {
				return
			}
			switch frame := frame.(type) {
			case *http2.SettingsFrame:
				if value, ok := frame.Value(http2.SettingInitialWindowSize); ok && !frame.IsAck() {
					preface.streamWindow = value
				}
			case *http2.WindowUpdateFrame:
				if frame.StreamID == 0 {
					preface.connectionWindow += frame.Increment
				}
			case *http2.HeadersFrame: // the first request: the preface is over
				prefaceDone <- preface
				io.Copy(io.Discard, reader)
				return
			}
		}
	}()
	dialer := hDialer{wrap: func(conn net.Conn) net.Conn { return &hFrameConn{Conn: conn, pipe: writer} }}
	transport, err := NewClient(context.Background(), dialer, serverAddr, option.V2RayGRPCOptions{ServiceName: "tun", V2RayGRPCWindowOptions: options}, nil)
	require.NoError(t, err)
	defer transport.Close()
	hDownload(t, transport.(*Client), 1)
	select {
	case preface := <-prefaceDone:
		return preface
	case <-time.After(5 * time.Second):
		t.Fatal("no request from the client")
		return hPreface{}
	}
}

// The client opens its windows before the first request, so a download does not wait for gRPC's
// estimate to grow them from 64 KiB.
func TestH_GRPCClientWindows(t *testing.T) {
	cases := []struct {
		name      string
		options   option.V2RayGRPCWindowOptions
		lowMemory bool
		expected  hPreface
	}{
		{"default", option.V2RayGRPCWindowOptions{}, false, hPreface{4 << 20, 16 << 20}},
		{"low memory", option.V2RayGRPCWindowOptions{}, true, hPreface{1 << 20, 16 << 20}},
		{"set", option.V2RayGRPCWindowOptions{InitialWindowSize: 1 << 20, InitialConnectionWindowSize: 2 << 20}, false, hPreface{1 << 20, 2 << 20}},
		{"connection below stream", option.V2RayGRPCWindowOptions{InitialWindowSize: 2 << 20, InitialConnectionWindowSize: 1 << 20}, false, hPreface{2 << 20, 2 << 20}},
		{"below HTTP/2's", option.V2RayGRPCWindowOptions{InitialWindowSize: 1000}, false, hPreface{0, 16 << 20}},
		{"dynamic", option.V2RayGRPCWindowOptions{InitialWindowSize: -1}, false, hPreface{0, 65535}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			lowMemory := common.LowMemory
			common.LowMemory = testCase.lowMemory
			defer func() { common.LowMemory = lowMemory }()
			require.Equal(t, testCase.expected, hClientPreface(t, testCase.options))
		})
	}
}

func TestH_GRPCWindowOptionsJSON(t *testing.T) {
	var options option.V2RayTransportOptions
	require.NoError(t, json.Unmarshal([]byte(`{"type":"grpc","service_name":"tun","initial_window_size":1048576,"initial_connection_window_size":-1}`), &options))
	require.Equal(t, "tun", options.GRPCOptions.ServiceName)
	require.EqualValues(t, 1<<20, options.GRPCOptions.InitialWindowSize)
	require.EqualValues(t, -1, options.GRPCOptions.InitialConnectionWindowSize)
}

// The first download on a new connection over a long round trip: with gRPC's windows of 64 KiB
// that grow from its estimate, 2 MB over 200 ms took about 2.1 s (ten round trips); with the
// windows open from the start, about 0.3 s.
func TestH_GRPCFirstDownloadOverLongRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("takes seconds")
	}
	const (
		roundTrip = 200 * time.Millisecond
		size      = 2_000_000
	)
	serverAddr := hStartSender(t)
	dialer := hDialer{wrap: func(conn net.Conn) net.Conn { return hNewDelayConn(conn, roundTrip/2) }}
	for _, testCase := range []struct {
		name    string
		options option.V2RayGRPCWindowOptions
		within  time.Duration
	}{
		{"default", option.V2RayGRPCWindowOptions{}, 5 * roundTrip},
		{"dynamic", option.V2RayGRPCWindowOptions{InitialWindowSize: -1}, 0},
	} {
		transport, err := NewClient(context.Background(), dialer, serverAddr, option.V2RayGRPCOptions{ServiceName: "tun", V2RayGRPCWindowOptions: testCase.options}, nil)
		require.NoError(t, err)
		first := hDownload(t, transport.(*Client), size)
		second := hDownload(t, transport.(*Client), size)
		transport.Close()
		t.Logf("%s: first %v, second %v", testCase.name, first.Round(time.Millisecond), second.Round(time.Millisecond))
		if testCase.within > 0 {
			require.Less(t, first, testCase.within, "the first download waited for the windows to grow")
		}
	}
}
