package tls

import (
	"context"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// runGateDials dials every destination at once through the gate, makes a handshake of 5 ms on
// each connection and returns the times of their ClientHellos.
func runGateDials(t *testing.T, server *gateDialer, destinations []M.Socksaddr) []time.Time {
	t.Helper()
	var hellos []time.Time
	var access sync.Mutex
	var wait sync.WaitGroup
	for _, destination := range destinations {
		wait.Add(1)
		go func() {
			defer wait.Done()
			conn, err := DialForHandshake(context.Background(), server, destination)
			if err != nil {
				t.Error(err)
				return
			}
			release, err := enterHandshake(context.Background(), conn, destination.AddrString())
			if err != nil {
				t.Error(err)
				return
			}
			access.Lock()
			hellos = append(hellos, time.Now())
			access.Unlock()
			time.Sleep(5 * time.Millisecond)
			server.open.Add(-1)
			release()
		}()
	}
	wait.Wait()
	return hellos
}

// checkGateQueue checks the connects and ClientHellos to one server against one queue of the
// gate: at most maxOpen connections from the connect to the end of the handshake, gap between two
// connects and between two ClientHellos, and never windowMax+1 connects within window.
func checkGateQueue(t *testing.T, server *gateDialer, hellos []time.Time, maxOpen int32, gap, window time.Duration, windowMax int) {
	t.Helper()
	if server.maxOpen.Load() > maxOpen {
		t.Fatalf("%d connections to the server open at once, max_inflight %d", server.maxOpen.Load(), maxOpen)
	}
	connects := append([]time.Time(nil), server.connects...)
	sort.Slice(connects, func(i, j int) bool { return connects[i].Before(connects[j]) })
	for i := 1; i < len(connects); i++ {
		if span := connects[i].Sub(connects[i-1]); span < gap {
			t.Fatalf("connects %d and %d only %v apart", i-1, i, span)
		}
	}
	for i := windowMax; i < len(connects); i++ {
		if span := connects[i].Sub(connects[i-windowMax]); span < window {
			t.Fatalf("connects %d..%d within %v", i-windowMax, i, span)
		}
	}
	sort.Slice(hellos, func(i, j int) bool { return hellos[i].Before(hellos[j]) })
	for i := 1; i < len(hellos); i++ {
		if span := hellos[i].Sub(hellos[i-1]); span < gap {
			t.Fatalf("ClientHellos %d and %d only %v apart", i-1, i, span)
		}
	}
}

func alternateDestinations(count int, destinations ...M.Socksaddr) []M.Socksaddr {
	var all []M.Socksaddr
	for i := 0; i < count; i++ {
		all = append(all, destinations[i%len(destinations)])
	}
	return all
}

// A server dialed both by its address and by its domain was two queues: the dials by domain took
// their turns at the domain, those by address at the address, and the two ran at once, each with
// a gap and a window of its own. Now a dial by domain counts at the address it reached, and the
// next ones by that domain take their turn there.
func TestH_HandshakeGateDomainAndAddressShareTheQueue(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(30 * time.Millisecond),
		MaxGap: badoption.Duration(40 * time.Millisecond), Window: badoption.Duration(400 * time.Millisecond), WindowMax: 3})
	defer SetHandshakeGate(nil)
	server := &gateDialer{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.50"), Port: 443}}
	byDomain, byAddress := M.ParseSocksaddr("server.example.com:443"), M.ParseSocksaddr("192.0.2.50:443")
	// the first dial by the domain finds its address
	hellos := runGateDials(t, server, []M.Socksaddr{byDomain})
	hellos = append(hellos, runGateDials(t, server, alternateDestinations(10, byDomain, byAddress))...)
	checkGateQueue(t, server, hellos, 1, 25*time.Millisecond, 395*time.Millisecond, 3)
}

// Two domains of one server were two queues as well. (The first dial of a domain, before the gate
// knows where it leads, connects without the gap; it keeps the gap to the ClientHello before it.)
func TestH_HandshakeGateTwoDomainsShareTheAddress(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(30 * time.Millisecond),
		MaxGap: badoption.Duration(40 * time.Millisecond), Window: badoption.Duration(400 * time.Millisecond), WindowMax: 3})
	defer SetHandshakeGate(nil)
	server := &gateDialer{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.51"), Port: 443}}
	first, second := M.ParseSocksaddr("a.example.com:443"), M.ParseSocksaddr("b.example.org:443")
	hellos := runGateDials(t, server, []M.Socksaddr{first})
	time.Sleep(50 * time.Millisecond)
	hellos = append(hellos, runGateDials(t, server, []M.Socksaddr{second})...)
	time.Sleep(50 * time.Millisecond)
	hellos = append(hellos, runGateDials(t, server, alternateDestinations(10, first, second))...)
	checkGateQueue(t, server, hellos, 1, 25*time.Millisecond, 395*time.Millisecond, 3)
}

// A domain whose address changes in DNS: the dial takes its turn at the old address it knew,
// counts at the new one it reached from the connect, ends at both, and the next dial takes its
// turn at the new one.
func TestH_HandshakeGateDomainMovesToANewAddress(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(40 * time.Millisecond)})
	defer SetHandshakeGate(nil)
	oldAddress := &net.TCPAddr{IP: net.ParseIP("192.0.2.60"), Port: 443}
	newAddress := &net.TCPAddr{IP: net.ParseIP("192.0.2.61"), Port: 443}
	byDomain := M.ParseSocksaddr("server.example.com:443")
	server := &gateDialer{remote: oldAddress}
	runGateDials(t, server, []M.Socksaddr{byDomain})
	server.remote = newAddress
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := DialForHandshake(ctx, server, byDomain)
	if err != nil {
		t.Fatal(err)
	}
	release, err := enterHandshake(ctx, conn, "server.example.com")
	if err != nil {
		t.Fatal(err)
	}
	// while its handshake runs, it is the one turn of the new address
	short, cancelShort := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelShort()
	if _, err := DialForHandshake(short, &gateDialer{remote: newAddress}, M.ParseSocksaddr("192.0.2.61:443")); err == nil {
		t.Fatal("a dial by the new address got a turn while the domain's handshake there ran")
	}
	short2, cancelShort2 := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelShort2()
	if _, err := enterHandshake(short2, addrConn{remote: newAddress}, "x"); err == nil {
		t.Fatal("a handshake to the new address got a turn while the domain's handshake there ran")
	}
	release()
	// ended at both: the old address and the new one are free
	holdOld, err := enterHandshake(ctx, addrConn{remote: oldAddress}, "x")
	if err != nil {
		t.Fatalf("the old address kept the turn: %v", err)
	}
	defer holdOld()
	// the next dial by the domain takes its turn at the new address, not at the old one now held
	next, cancelNext := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancelNext()
	conn, err = DialForHandshake(next, server, byDomain)
	if err != nil {
		t.Fatalf("the domain still waits at its old address: %v", err)
	}
	release, err = enterHandshake(next, conn, "server.example.com")
	if err != nil {
		t.Fatal(err)
	}
	release()
}

// A dial by domain does not wait at the address it reached: the turn was its own before the
// connect, and its handshake waits only for the gap since the previous ClientHello there.
func TestH_HandshakeGateDomainConnectDoesNotWait(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(time.Millisecond)})
	defer SetHandshakeGate(nil)
	address := &net.TCPAddr{IP: net.ParseIP("192.0.2.62"), Port: 443}
	hold, err := enterHandshake(context.Background(), addrConn{remote: address}, "x")
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	conn, err := DialForHandshake(ctx, &gateDialer{remote: address}, M.ParseSocksaddr("new.example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	release, err := enterHandshake(ctx, conn, "new.example.com")
	if err != nil {
		t.Fatal(err)
	}
	release()
	if waited := time.Since(start); waited > 100*time.Millisecond {
		t.Fatalf("the first dial by a domain waited %v at the address it reached", waited)
	}
}

type detourOutbound struct {
	adapter.Outbound
	through N.Dialer
}

func (o *detourOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.through.DialContext(ctx, network, destination)
}

type detourManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *detourManager) Outbound(string) (adapter.Outbound, bool) { return m.outbound, true }

// A dial by domain through another outbound reaches that outbound's server: it is counted by the
// domain, as before, and the detour's server is not taken for the domain's.
func TestH_HandshakeGateDomainThroughADetour(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(time.Millisecond)})
	defer SetHandshakeGate(nil)
	gate := activeGate.Load()
	detourServer := &net.TCPAddr{IP: net.ParseIP("192.0.2.80"), Port: 443}
	through := dialer.NewDetour(&detourManager{outbound: &detourOutbound{through: &gateDialer{remote: detourServer}}}, "proxy", true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		conn, err := DialForHandshake(ctx, through, M.ParseSocksaddr("server.example.com:443"))
		if err != nil {
			t.Fatal(err)
		}
		gate.access.Lock()
		byDomain := gate.servers[gateKey{host: "server.example.com"}]
		inflight := byDomain != nil && byDomain.inflight == 1
		gate.access.Unlock()
		if !inflight {
			t.Fatalf("dial %d: the turn is not the domain's", i)
		}
		short, cancelShort := context.WithTimeout(context.Background(), 100*time.Millisecond)
		hold, err := enterHandshake(short, addrConn{remote: detourServer}, "x")
		cancelShort()
		if err != nil {
			t.Fatalf("dial %d: the detour's server was counted for the domain: %v", i, err)
		}
		hold()
		release, err := enterHandshake(ctx, conn, "server.example.com")
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
}

// recordingDialer is a gateDialer that records the destinations it was asked for.
type recordingDialer struct {
	gateDialer
	dials []string
}

func (d *recordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.dials = append(d.dials, network+" "+destination.String())
	d.access.Unlock()
	return d.gateDialer.DialContext(ctx, network, destination)
}

// gateServers is, for each server the gate knows, its turns in flight, its starts in the window
// and whether a ClientHello to it was let go.
func gateServers(gate *handshakeGate) map[string][3]int {
	gate.access.Lock()
	defer gate.access.Unlock()
	servers := map[string][3]int{}
	for key, state := range gate.servers {
		hello := 0
		if !state.lastHello.IsZero() {
			hello = 1
		}
		servers[key.server.String()+"|"+key.host] = [3]int{state.inflight, len(state.starts), hello}
	}
	return servers
}

func sameServers(t *testing.T, step string, got, want map[string][3]int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: servers %v, want %v", step, got, want)
	}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("%s: servers %v, want %v", step, got, want)
		}
	}
}

// A dial by address goes as before: one connect to the destination, the turn taken at the
// destination's address (not at the address the connection reports), the ClientHello counted at
// the connection's address, and the turn ended at the destination's.
func TestH_HandshakeGateAddressDialAsBefore(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 2, MinGap: badoption.Duration(time.Millisecond),
		Window: badoption.Duration(time.Minute), WindowMax: 10})
	defer SetHandshakeGate(nil)
	gate := activeGate.Load()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, remote := range []string{"192.0.2.70", "192.0.2.71"} {
		server := &recordingDialer{gateDialer: gateDialer{remote: &net.TCPAddr{IP: net.ParseIP(remote), Port: 443}}}
		conn, err := DialForHandshake(ctx, server, M.ParseSocksaddr("192.0.2.70:443"))
		if err != nil {
			t.Fatal(err)
		}
		if len(server.dials) != 1 || server.dials[0] != "tcp 192.0.2.70:443" {
			t.Fatalf("dials %v", server.dials)
		}
		gate.access.Lock()
		tickets := len(gate.tickets)
		gate.access.Unlock()
		if tickets != 1 {
			t.Fatalf("%d tickets", tickets)
		}
		dialed := map[string][3]int{"192.0.2.70/32|": {1, 1, 0}}
		handshake := map[string][3]int{"192.0.2.70/32|": {1, 1, 1}}
		ended := map[string][3]int{"192.0.2.70/32|": {0, 1, 1}}
		if remote == "192.0.2.71" {
			dialed = map[string][3]int{"192.0.2.70/32|": {1, 2, 1}}
			handshake = map[string][3]int{"192.0.2.70/32|": {1, 2, 1}, "192.0.2.71/32|": {0, 0, 1}}
			ended = map[string][3]int{"192.0.2.70/32|": {0, 2, 1}, "192.0.2.71/32|": {0, 0, 1}}
		}
		sameServers(t, "dialed", gateServers(gate), dialed)
		release, err := enterHandshake(ctx, conn, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		sameServers(t, "handshake", gateServers(gate), handshake)
		release()
		release()
		sameServers(t, "ended", gateServers(gate), ended)
	}
}
