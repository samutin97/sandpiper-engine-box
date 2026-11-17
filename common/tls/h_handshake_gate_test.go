package tls

import (
	"context"
	"errors"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

func TestH_HandshakeGatePaces(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 3, MinGap: badoption.Duration(100 * time.Millisecond)})
	defer SetHandshakeGate(nil)
	conn := addrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}}
	var inflight, maxInflight atomic.Int32
	var starts []time.Time
	var access sync.Mutex
	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			release, err := enterHandshake(context.Background(), conn, "example.com")
			if err != nil {
				t.Error(err)
				return
			}
			access.Lock()
			starts = append(starts, time.Now())
			access.Unlock()
			if n := inflight.Add(1); n > maxInflight.Load() {
				maxInflight.Store(n)
			}
			time.Sleep(250 * time.Millisecond) // a slow handshake
			inflight.Add(-1)
			release()
		}()
	}
	wait.Wait()
	if maxInflight.Load() > 3 {
		t.Fatalf("%d handshakes at once", maxInflight.Load())
	}
	for i := 1; i < len(starts); i++ {
		if gap := starts[i].Sub(starts[i-1]); gap < 90*time.Millisecond {
			t.Fatalf("starts %d and %d only %v apart", i-1, i, gap)
		}
	}
	// another address is another counter: no wait
	start := time.Now()
	other := addrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 443}}
	release, _ := enterHandshake(context.Background(), other, "example.com")
	release()
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("a different server waited")
	}
}

func TestH_HandshakeGateCancel(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(time.Hour)})
	defer SetHandshakeGate(nil)
	conn := addrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 443}}
	release, err := enterHandshake(context.Background(), conn, "x")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := enterHandshake(ctx, conn, "x"); err == nil {
		t.Fatal("no wait for the gap")
	}
	SetHandshakeGate(nil)
	if r, err := enterHandshake(context.Background(), conn, "x"); err != nil {
		t.Fatal("gate off still waits")
	} else {
		r()
	}
}

// gateConn is a connected TCP connection of a fake dialer: only its addresses matter.
type gateConn struct {
	net.Conn
	local, remote net.Addr
}

func (c *gateConn) LocalAddr() net.Addr  { return c.local }
func (c *gateConn) RemoteAddr() net.Addr { return c.remote }
func (c *gateConn) Close() error         { return nil }

// gateDialer connects at once, to remote, from a new local port each time, and counts the
// connections open from their connect until the test ends their handshake.
type gateDialer struct {
	remote   net.Addr
	port     atomic.Int32
	open     atomic.Int32
	maxOpen  atomic.Int32
	fail     bool
	access   sync.Mutex
	connects []time.Time
}

func (d *gateDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if d.fail {
		return nil, errors.New("refused")
	}
	d.access.Lock()
	if n := d.open.Add(1); n > d.maxOpen.Load() {
		d.maxOpen.Store(n)
	}
	d.connects = append(d.connects, time.Now())
	d.access.Unlock()
	local := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40000 + int(d.port.Add(1))}
	return &gateConn{local: local, remote: d.remote}, nil
}

func (d *gateDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// Four connections were open to a server at once, the fourth waiting for the gate after its TCP
// connect, and each server name was a counter of its own. Now a dial for a handshake waits before
// the connect, and the address counts.
func TestH_HandshakeGateCountsFromTheConnect(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 3, MinGap: badoption.Duration(60 * time.Millisecond)})
	defer SetHandshakeGate(nil)
	server := &net.TCPAddr{IP: net.ParseIP("192.0.2.30"), Port: 443}
	names := []string{"a.example.com", "b.example.com", "c.example.com"}
	for _, destination := range []M.Socksaddr{M.ParseSocksaddr("192.0.2.30:443"), M.ParseSocksaddr("server.example.com:443")} {
		dialer := &gateDialer{remote: server}
		var hellos []time.Time
		var access sync.Mutex
		var wait sync.WaitGroup
		for i := 0; i < 9; i++ {
			wait.Add(1)
			go func(i int) {
				defer wait.Done()
				conn, err := DialForHandshake(context.Background(), dialer, destination)
				if err != nil {
					t.Error(err)
					return
				}
				// each node of a subscription may have a name of its own on the same server
				release, err := enterHandshake(context.Background(), conn, names[i%3])
				if err != nil {
					t.Error(err)
					return
				}
				access.Lock()
				hellos = append(hellos, time.Now())
				access.Unlock()
				time.Sleep(100 * time.Millisecond) // the handshake
				dialer.open.Add(-1)
				release()
			}(i)
		}
		wait.Wait()
		if dialer.maxOpen.Load() > 3 {
			t.Fatalf("%v: %d connections open before their handshake ended", destination, dialer.maxOpen.Load())
		}
		sort.Slice(hellos, func(i, j int) bool { return hellos[i].Before(hellos[j]) })
		for i := 1; i < len(hellos); i++ {
			if gap := hellos[i].Sub(hellos[i-1]); gap < 55*time.Millisecond {
				t.Fatalf("%v: ClientHellos %d and %d only %v apart", destination, i-1, i, gap)
			}
		}
		for i := 1; i < len(dialer.connects); i++ {
			if gap := dialer.connects[i].Sub(dialer.connects[i-1]); gap < 55*time.Millisecond {
				t.Fatalf("%v: connects %d and %d only %v apart", destination, i-1, i, gap)
			}
		}
	}
}

func TestH_HandshakeGateNamesShareTheAddress(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 3, MinGap: badoption.Duration(time.Millisecond)})
	defer SetHandshakeGate(nil)
	conn := addrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.31"), Port: 443}}
	var releases []func()
	for _, name := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		release, err := enterHandshake(context.Background(), conn, name)
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
		time.Sleep(2 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := enterHandshake(ctx, conn, "d.example.com"); err == nil {
		t.Fatal("a fourth name to the same address got a turn")
	}
	releases[0]()
	release, err := enterHandshake(context.Background(), conn, "d.example.com")
	if err != nil {
		t.Fatal(err)
	}
	release()
	releases[1]()
	releases[2]()
}

// The turn taken at the dial is the handshake's: with one turn the handshake must not wait for a
// second (it would wait for itself).
func TestH_HandshakeGateDialTurnIsTheHandshakes(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(time.Millisecond)})
	defer SetHandshakeGate(nil)
	dialer := &gateDialer{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.32"), Port: 443}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		conn, err := DialForHandshake(ctx, dialer, M.ParseSocksaddr("192.0.2.32:443"))
		if err != nil {
			t.Fatal(err)
		}
		release, err := enterHandshake(ctx, conn, "example.com")
		if err != nil {
			t.Fatalf("handshake %d: %v", i, err)
		}
		release()
	}
}

// A turn is freed when the dial fails, and when no handshake follows the dial.
func TestH_HandshakeGateFreesUnusedTurns(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(time.Millisecond)})
	defer SetHandshakeGate(nil)
	hold := dialTicketHold
	dialTicketHold = 50 * time.Millisecond
	defer func() { dialTicketHold = hold }()
	destination := M.ParseSocksaddr("192.0.2.33:443")
	failing := &gateDialer{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.33"), Port: 443}, fail: true}
	if _, err := DialForHandshake(context.Background(), failing, destination); err == nil {
		t.Fatal("no error")
	}
	dialer := &gateDialer{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.33"), Port: 443}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := DialForHandshake(ctx, dialer, destination); err != nil {
		t.Fatalf("the failed dial kept its turn: %v", err)
	}
	// the dial above never handshakes: its turn is back after the hold
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	start := time.Now()
	conn, err := DialForHandshake(ctx2, dialer, destination)
	if err != nil {
		t.Fatalf("the unused turn was not freed: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("waited past the hold")
	}
	release, err := enterHandshake(ctx2, conn, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	release()
}
