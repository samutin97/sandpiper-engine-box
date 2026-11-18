package tls

import (
	"context"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// dialUnseen dials destination count times at once through dialer, as cronet takes its sockets:
// the handshake follows on the connection without the gate seeing it, and nothing ends it. It
// returns when each dial returned (when the ClientHello would go).
func dialUnseen(t *testing.T, dialer N.Dialer, destination M.Socksaddr, count int) []time.Time {
	t.Helper()
	var hellos []time.Time
	var access sync.Mutex
	var wait sync.WaitGroup
	for i := 0; i < count; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
			if err != nil {
				t.Error(err)
				return
			}
			access.Lock()
			hellos = append(hellos, time.Now())
			access.Unlock()
			_ = conn.Close() // cronet keeps a duplicate of the socket and closes this one at once
		}()
	}
	wait.Wait()
	sort.Slice(hellos, func(i, j int) bool { return hellos[i].Before(hellos[j]) })
	return hellos
}

// A naive outbound's handshakes, made by cronet on the sockets of the outbound's dialer, went past
// the gate: four dials to one server connected at once. Through GateDialer they take the server's
// turn before the connect, keep the gap, and each turn ends unseen_hold after its connect (not
// after the 8 s of an unused dial's ticket).
func TestH_HandshakeGateUnseenHandshakes(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(20 * time.Millisecond),
		UnseenHold: badoption.Duration(150 * time.Millisecond)})
	defer SetHandshakeGate(nil)
	server := &gateDialer{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.100"), Port: 443}}
	start := time.Now()
	hellos := dialUnseen(t, GateDialer(server), M.ParseSocksaddr("192.0.2.100:443"), 4)
	connects := append([]time.Time(nil), server.connects...)
	sort.Slice(connects, func(i, j int) bool { return connects[i].Before(connects[j]) })
	if len(connects) != 4 {
		t.Fatalf("%d connects", len(connects))
	}
	for i := 1; i < len(connects); i++ {
		// one turn: the next connect waits for the hold after the previous one
		if span := connects[i].Sub(connects[i-1]); span < 140*time.Millisecond {
			t.Fatalf("connects %d and %d only %v apart", i-1, i, span)
		}
	}
	if total := time.Since(start); total > 2*time.Second {
		t.Fatalf("four dials took %v: the turns were held past unseen_hold", total)
	}
	// and a handshake the gate sees, to the same address, waits for the last unseen one
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := enterHandshake(ctx, addrConn{remote: server.remote}, "x"); err == nil {
		t.Fatal("a handshake got a turn while an unseen one held it")
	}
	for i := 1; i < len(hellos); i++ {
		if span := hellos[i].Sub(hellos[i-1]); span < 18*time.Millisecond {
			t.Fatalf("ClientHellos %d and %d only %v apart", i-1, i, span)
		}
	}
}

// Without a gate, and for datagrams, the dialer is the outbound's, untouched.
func TestH_HandshakeGateUnseenPassThrough(t *testing.T) {
	SetHandshakeGate(nil)
	server := &gateDialer{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.101"), Port: 443}}
	start := time.Now()
	dialUnseen(t, GateDialer(server), M.ParseSocksaddr("192.0.2.101:443"), 3)
	if len(server.connects) != 3 || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("without a gate: %d connects in %v", len(server.connects), time.Since(start))
	}
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(time.Hour)})
	defer SetHandshakeGate(nil)
	if _, err := GateDialer(server).ListenPacket(context.Background(), M.ParseSocksaddr("192.0.2.101:443")); err == nil {
		t.Fatal("ListenPacket did not reach the dialer")
	}
	if gate := activeGate.Load(); gate.unseenHold != DefaultGateUnseenHold {
		t.Fatalf("default unseen_hold %v", gate.unseenHold)
	}
}
