package tls

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// The handshake gate paces the TLS handshakes of the outbounds to one server (address or subnet,
// and server name): at most max_inflight at a time, and min_gap between the starts of two. A
// Russian DPI counts the TLS handshakes to one (IP, SNI): more than three in parallel, or a quick
// series, freezes the server for the client for about two minutes, and some ~12 attempts in a row
// cut the hybrid ClientHello. A browser opening twenty connections through a proxy without a
// multiplexing transport, a URL test, a reconnection after a network change: all of them
// handshake at once. Every TLS client handshake of the outbounds goes through ClientHandshake
// and the TLS dialer here, so all of them wait their turn. //H

type handshakeGate struct {
	maxInflight int
	minGap      time.Duration
	prefix4     int
	prefix6     int
	access      sync.Mutex
	servers     map[gateKey]*gateState
}

type gateKey struct {
	server     netip.Prefix
	serverName string
}

type gateState struct {
	inflight  int
	lastStart time.Time
	changed   chan struct{} // closed and replaced when a handshake ends
}

var activeGate atomic.Pointer[handshakeGate]

// Defaults of handshake_gate when enabled without values.
const (
	DefaultGateMaxInflight = 3
	DefaultGateMinGap      = 450 * time.Millisecond
)

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

// enterHandshake waits for the turn of a handshake on conn to serverName, and returns the
// function to call when it ends. Without a gate it returns at once. //H
func enterHandshake(ctx context.Context, conn net.Conn, serverName string) (func(), error) {
	gate := activeGate.Load()
	if gate == nil || conn == nil {
		return func() {}, nil
	}
	return gate.enter(ctx, gate.keyOf(conn.RemoteAddr(), serverName))
}

func (g *handshakeGate) keyOf(remote net.Addr, serverName string) gateKey {
	key := gateKey{serverName: serverName}
	if remote == nil {
		return key
	}
	addr := M.AddrPortFromNet(remote).Addr().Unmap()
	if !addr.IsValid() {
		return key
	}
	bits := g.prefix6
	if addr.Is4() {
		bits = g.prefix4
	}
	if prefix, err := addr.Prefix(bits); err == nil {
		key.server = prefix
	}
	return key
}

func (g *handshakeGate) enter(ctx context.Context, key gateKey) (func(), error) {
	for {
		g.access.Lock()
		state := g.servers[key]
		if state == nil {
			if len(g.servers) > 256 {
				g.sweep()
			}
			state = &gateState{changed: make(chan struct{})}
			g.servers[key] = state
		}
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
		g.access.Unlock()
		var timer *time.Timer
		var tick <-chan time.Time
		if state.inflight < g.maxInflight || wait > 0 {
			if wait <= 0 {
				wait = time.Millisecond
			}
			timer = time.NewTimer(wait)
			tick = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil, ctx.Err()
		case <-changed:
		case <-tick:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// sweep forgets the servers without a handshake in the last minute; access must be held.
func (g *handshakeGate) sweep() {
	for key, state := range g.servers {
		if state.inflight <= 0 && time.Since(state.lastStart) > time.Minute {
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
