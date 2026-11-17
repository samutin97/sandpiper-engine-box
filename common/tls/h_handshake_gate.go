package tls

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The handshake gate paces the TLS handshakes of the outbounds to one server (an address, or a
// subnet): at most max_inflight at a time, and min_gap between the starts of two. A Russian DPI
// counts the TLS handshakes to one server: more than three in parallel, or a quick series, freezes
// the server for the client for about two minutes, and some ~12 attempts in a row cut the hybrid
// ClientHello. A browser opening twenty connections through a proxy without a multiplexing
// transport, a URL test, a reconnection after a network change: all of them handshake at once.
//
// What counts is the server's address, not the server name: handshakes with several names to one
// address are one series for the DPI. A handshake counts from its TCP connect when the connection
// was dialed through DialForHandshake (the outbounds' TLS dials: the TLS dialer, VLESS, XHTTP,
// gRPC), so a connection waiting for its turn is not left open without a ClientHello: the turn is
// taken before the connect and kept until the handshake ends. Such a dial is counted by the
// destination as the outbound gives it (an address, or a domain before it is resolved). Every
// ClientHello to an address, dialed so or not, also keeps min_gap from the previous one there. //H

type handshakeGate struct {
	maxInflight int
	minGap      time.Duration
	prefix4     int
	prefix6     int
	access      sync.Mutex
	servers     map[gateKey]*gateState
	tickets     map[string]*dialTicket
}

// gateKey is a server: its address (subnet), or its domain for a dial not resolved yet.
type gateKey struct {
	server netip.Prefix
	host   string
}

type gateState struct {
	inflight  int
	lastStart time.Time     // the last turn taken
	lastHello time.Time     // the last ClientHello let go
	changed   chan struct{} // closed and replaced when a turn ends
}

// dialTicket is the turn a connection took at its dial, kept until its handshake ends.
type dialTicket struct {
	id    string
	once  sync.Once
	end   func()
	timer *time.Timer
}

var activeGate atomic.Pointer[handshakeGate]

// Defaults of handshake_gate when enabled without values.
const (
	DefaultGateMaxInflight = 3
	DefaultGateMinGap      = 450 * time.Millisecond
)

// dialTicketHold is how long a dial's turn waits for its handshake: a dial that is never followed
// by one (an error in between) frees its turn then.
var dialTicketHold = 8 * time.Second

// SetHandshakeGate configures the gate of the process from a config; nil or disabled turns it
// off. The last box started sets it. //H
func SetHandshakeGate(options *option.HandshakeGateOptions) {
	if options == nil || !options.Enabled {
		activeGate.Store(nil)
		return
	}
	gate := &handshakeGate{
		maxInflight: options.MaxInflight,
		minGap:      time.Duration(options.MinGap),
		prefix4:     options.IPv4Prefix,
		prefix6:     options.IPv6Prefix,
		servers:     map[gateKey]*gateState{},
		tickets:     map[string]*dialTicket{},
	}
	if gate.maxInflight <= 0 {
		gate.maxInflight = DefaultGateMaxInflight
	}
	if gate.minGap <= 0 {
		gate.minGap = DefaultGateMinGap
	}
	if gate.prefix4 <= 0 || gate.prefix4 > 32 {
		gate.prefix4 = 32
	}
	if gate.prefix6 <= 0 || gate.prefix6 > 128 {
		gate.prefix6 = 128
	}
	activeGate.Store(gate)
}

// DialForHandshake dials destination over TCP for a TLS handshake that follows on the connection:
// the connect waits for the server's turn in the gate, and the turn is kept until ClientHandshake
// on the connection ends (or dialTicketHold passes). Without a gate it is a plain dial. //H
func DialForHandshake(ctx context.Context, dialer N.Dialer, destination M.Socksaddr) (net.Conn, error) {
	gate := activeGate.Load()
	if gate == nil {
		return dialer.DialContext(ctx, N.NetworkTCP, destination)
	}
	end, err := gate.enter(ctx, gate.destinationKey(destination))
	if err != nil {
		return nil, err
	}
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		end()
		return nil, err
	}
	if !gate.addTicket(conn, end) {
		// a connection without addresses cannot be found again: its handshake takes a turn of its own
		end()
	}
	return conn, nil
}

// enterHandshake waits for the turn of a handshake on conn, and returns the function to call
// when it ends. Without a gate it returns at once. The server name is not part of the turn (see
// above). //H
func enterHandshake(ctx context.Context, conn net.Conn, serverName string) (func(), error) {
	gate := activeGate.Load()
	if gate == nil || conn == nil {
		return func() {}, nil
	}
	key := gate.addressKey(conn.RemoteAddr())
	if ticket := gate.takeTicket(conn); ticket != nil {
		// the turn was taken at the dial: only the gap to the previous ClientHello is left
		if err := gate.waitHello(ctx, key); err != nil {
			ticket.done()
			return nil, err
		}
		return ticket.done, nil
	}
	end, err := gate.enter(ctx, key)
	if err != nil {
		return nil, err
	}
	if err := gate.waitHello(ctx, key); err != nil {
		end()
		return nil, err
	}
	return end, nil
}

func (g *handshakeGate) addressKey(remote net.Addr) gateKey {
	if remote == nil {
		return gateKey{}
	}
	return g.prefixKey(M.AddrPortFromNet(remote).Addr())
}

func (g *handshakeGate) destinationKey(destination M.Socksaddr) gateKey {
	if destination.IsIP() {
		return g.prefixKey(destination.Addr)
	}
	return gateKey{host: strings.ToLower(strings.TrimSuffix(destination.Fqdn, "."))}
}

func (g *handshakeGate) prefixKey(addr netip.Addr) gateKey {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return gateKey{}
	}
	bits := g.prefix6
	if addr.Is4() {
		bits = g.prefix4
	}
	if prefix, err := addr.Prefix(bits); err == nil {
		return gateKey{server: prefix}
	}
	return gateKey{}
}

// state returns the server's state; access must be held.
func (g *handshakeGate) state(key gateKey) *gateState {
	state := g.servers[key]
	if state == nil {
		if len(g.servers) > 256 {
			g.sweep()
		}
		state = &gateState{changed: make(chan struct{})}
		g.servers[key] = state
	}
	return state
}

// enter takes a turn of the server: fewer than maxInflight taken, and minGap since the last one.
func (g *handshakeGate) enter(ctx context.Context, key gateKey) (func(), error) {
	for {
		g.access.Lock()
		state := g.state(key)
		now := time.Now()
		wait := g.minGap - now.Sub(state.lastStart)
		if state.inflight < g.maxInflight && wait <= 0 {
			state.inflight++
			state.lastStart = now
			g.access.Unlock()
			var once sync.Once
			return func() { once.Do(func() { g.leave(key) }) }, nil
		}
		changed := state.changed
		full := state.inflight >= g.maxInflight
		g.access.Unlock()
		if err := g.sleep(ctx, changed, full, wait); err != nil {
			return nil, err
		}
	}
}

// waitHello waits until minGap passed since the last ClientHello to the server, and counts this one.
func (g *handshakeGate) waitHello(ctx context.Context, key gateKey) error {
	for {
		g.access.Lock()
		state := g.state(key)
		now := time.Now()
		wait := g.minGap - now.Sub(state.lastHello)
		if wait <= 0 {
			state.lastHello = now
			g.access.Unlock()
			return nil
		}
		g.access.Unlock()
		if err := g.sleep(ctx, nil, false, wait); err != nil {
			return err
		}
	}
}

// sleep waits for a turn to end (full) or for wait to pass, or for ctx.
func (g *handshakeGate) sleep(ctx context.Context, changed chan struct{}, full bool, wait time.Duration) error {
	var tick <-chan time.Time
	if !full || wait > 0 {
		if wait <= 0 {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		tick = timer.C
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-changed:
	case <-tick:
	}
	return nil
}

// sweep forgets the servers without a turn in the last minute; access must be held.
func (g *handshakeGate) sweep() {
	for key, state := range g.servers {
		if state.inflight <= 0 && time.Since(state.lastStart) > time.Minute && time.Since(state.lastHello) > time.Minute {
			delete(g.servers, key)
		}
	}
}

func (g *handshakeGate) leave(key gateKey) {
	g.access.Lock()
	defer g.access.Unlock()
	state := g.servers[key]
	if state == nil {
		return
	}
	state.inflight--
	close(state.changed)
	state.changed = make(chan struct{})
}

// connectionID is a TCP connection's addresses, or "" when it has none (or cannot tell them).
func connectionID(conn net.Conn) (id string) {
	defer func() {
		if recover() != nil {
			id = ""
		}
	}()
	local, remote := conn.LocalAddr(), conn.RemoteAddr()
	if local == nil || remote == nil {
		return ""
	}
	return local.Network() + " " + local.String() + " " + remote.String()
}

// addTicket keeps the dial's turn for the handshake on conn; false when conn cannot be found again.
func (g *handshakeGate) addTicket(conn net.Conn, end func()) bool {
	id := connectionID(conn)
	if id == "" {
		return false
	}
	ticket := &dialTicket{id: id}
	ticket.end = func() {
		g.access.Lock()
		if g.tickets[id] == ticket {
			delete(g.tickets, id)
		}
		g.access.Unlock()
		end()
	}
	g.access.Lock()
	if previous := g.tickets[id]; previous != nil {
		// a connection of the same addresses that never handshook: its turn is over
		g.access.Unlock()
		previous.done()
		g.access.Lock()
	}
	g.tickets[id] = ticket
	ticket.timer = time.AfterFunc(dialTicketHold, ticket.done)
	g.access.Unlock()
	return true
}

// takeTicket returns the turn conn took at its dial, if it is still kept; the wrappers of a
// connection (fragmenting, counting) keep its addresses.
func (g *handshakeGate) takeTicket(conn net.Conn) *dialTicket {
	g.access.Lock()
	none := len(g.tickets) == 0
	g.access.Unlock()
	if none {
		return nil
	}
	id := connectionID(conn)
	if id == "" {
		return nil
	}
	g.access.Lock()
	defer g.access.Unlock()
	ticket := g.tickets[id]
	if ticket == nil {
		return nil
	}
	delete(g.tickets, id)
	if ticket.timer != nil && !ticket.timer.Stop() {
		// the hold ran out just now: its turn is being freed, the handshake takes a new one
		return nil
	}
	return ticket
}

// done frees the turn once: at the end of the handshake, or when the hold runs out (the timer is
// stopped by takeTicket before a handshake uses the ticket).
func (t *dialTicket) done() {
	t.once.Do(t.end)
}
