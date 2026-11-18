package tls

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

// The gate remembers at most gateNamesMax domains, forgetting the one dialed longest ago, and
// sweep forgets the domains not dialed for a while along with the idle servers.
func TestH_HandshakeGateRemembersBoundedDomains(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MinGap: badoption.Duration(time.Millisecond)})
	defer SetHandshakeGate(nil)
	gate := activeGate.Load()
	address := gate.prefixKey(netip.MustParseAddr("192.0.2.90"))
	base := time.Now()
	gate.access.Lock()
	defer gate.access.Unlock()
	for i := 0; i < gateNamesMax+40; i++ {
		gate.remember(fmt.Sprintf("n%d.example.com", i), address, base.Add(time.Duration(i)*time.Millisecond))
	}
	if len(gate.names) != gateNamesMax {
		t.Fatalf("%d domains remembered", len(gate.names))
	}
	for i := 0; i < 40; i++ {
		if _, kept := gate.names[fmt.Sprintf("n%d.example.com", i)]; kept {
			t.Fatalf("n%d, dialed longest ago, is kept", i)
		}
	}
	// a domain known already takes no other's place
	gate.remember("n40.example.com", address, base.Add(time.Hour))
	if len(gate.names) != gateNamesMax {
		t.Fatalf("%d domains after a known one", len(gate.names))
	}
	if _, kept := gate.names["n41.example.com"]; !kept {
		t.Fatal("a known domain pushed another out")
	}
	for i := 41; i < 100; i++ {
		host := fmt.Sprintf("n%d.example.com", i)
		gate.names[host] = gateName{address: address, used: base.Add(-time.Hour)}
	}
	gate.sweep()
	if len(gate.names) != gateNamesMax-59 {
		t.Fatalf("%d domains after the sweep", len(gate.names))
	}
	if _, kept := gate.names["n41.example.com"]; kept {
		t.Fatal("the sweep kept a domain idle for an hour")
	}
	if _, kept := gate.names["n40.example.com"]; !kept {
		t.Fatal("the sweep forgot a domain just dialed")
	}
}

// heldDialer is a gateDialer whose connect waits for proceed.
type heldDialer struct {
	gateDialer
	proceed chan struct{}
}

func (d *heldDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	<-d.proceed
	return d.gateDialer.DialContext(ctx, network, destination)
}

// A dial by domain that waits behind the domain's first one moves to the address the first one
// reaches, as soon as it reaches it.
func TestH_HandshakeGateWaitingDomainMovesToTheAddress(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(time.Millisecond)})
	defer SetHandshakeGate(nil)
	gate := activeGate.Load()
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.91"), Port: 443}
	address := gate.prefixKey(netip.MustParseAddr("192.0.2.91"))
	name := gateKey{host: "server.example.com"}
	destination := M.ParseSocksaddr("server.example.com:443")
	inflight := func(key gateKey) int {
		gate.access.Lock()
		defer gate.access.Unlock()
		if state := gate.servers[key]; state != nil {
			return state.inflight
		}
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	held := &heldDialer{gateDialer: gateDialer{remote: remote}, proceed: make(chan struct{})}
	first := make(chan net.Conn, 1)
	go func() {
		conn, err := DialForHandshake(ctx, held, destination)
		if err != nil {
			t.Error(err)
		}
		first <- conn
	}()
	for inflight(name) != 1 {
		time.Sleep(time.Millisecond)
	}
	second := make(chan net.Conn, 1)
	go func() {
		conn, err := DialForHandshake(ctx, &gateDialer{remote: remote}, destination)
		if err != nil {
			t.Error(err)
		}
		second <- conn
	}()
	time.Sleep(20 * time.Millisecond)
	close(held.proceed)
	conn := <-first
	if conn == nil {
		t.FailNow()
	}
	time.Sleep(20 * time.Millisecond)
	select {
	case <-second:
		t.Fatal("the second dial did not wait for the first's handshake")
	default:
	}
	if inflight(name) != 1 || inflight(address) != 1 {
		t.Fatalf("the first dial: %d at the domain, %d at the address", inflight(name), inflight(address))
	}
	release, err := enterHandshake(ctx, conn, "server.example.com")
	if err != nil {
		t.Fatal(err)
	}
	release()
	conn = <-second
	if conn == nil {
		t.FailNow()
	}
	if inflight(name) != 0 || inflight(address) != 1 {
		t.Fatalf("the second dial: %d at the domain, %d at the address", inflight(name), inflight(address))
	}
	release, err = enterHandshake(ctx, conn, "server.example.com")
	if err != nil {
		t.Fatal(err)
	}
	release()
	if inflight(name) != 0 || inflight(address) != 0 {
		t.Fatalf("ended: %d at the domain, %d at the address", inflight(name), inflight(address))
	}
}
