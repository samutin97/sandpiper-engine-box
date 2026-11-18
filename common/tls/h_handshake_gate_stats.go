package tls

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// What the handshake gate did, for a journal of what stopped getting through: a block that follows
// a series of handshakes to one server is told apart from one that does not only by counting them.
// The gate counts, for each server (its key: an address as address/bits, or a domain), the turns
// taken, how many of them waited and for what, the ClientHellos let go and the TCP connects that
// failed after a turn; TakeHandshakeGateStats hands the counts over and starts them again. The
// counts live outside the gate, so a new config (a new gate) does not lose them.
//
// A DialTrace in a dial's context records what that one dial did on its way through the gate (or
// past it, without one): the wait for its turn, the TCP connect and whether the ClientHello went
// out, so that a failed dial through a proxy is told apart as a TCP connect that failed, or a
// handshake (TLS, REALITY, the proxy's own) that did not end. Neither changes what the gate does.

// HandshakeGateStat is what the gate counted for one server since the last TakeHandshakeGateStats.
type HandshakeGateStat struct {
	Server        string        // address/bits, or a domain while the gate knew no address for it
	Turns         int           // turns taken: dials for a handshake, and handshakes without one
	Waited        int           // turns that waited before they were taken
	WaitMax       time.Duration // the longest of those waits
	WaitTotal     time.Duration // all of them
	Full          int           // turns that waited for a place in max_inflight
	Window        int           // turns that waited for the window (window_max reached)
	Hellos        int           // ClientHellos let go to the address
	ConnectFailed int           // TCP connects after a turn that failed
}

// gateStatsMax bounds the servers counted between two takes; the others are counted as one, with
// the server "other".
const gateStatsMax = 256

var gateStats struct {
	access  sync.Mutex
	servers map[string]*HandshakeGateStat
}

// TakeHandshakeGateStats returns the counts of each server since the last call, the busiest first,
// and starts them again; nil when nothing was counted. //H
func TakeHandshakeGateStats() []HandshakeGateStat {
	gateStats.access.Lock()
	servers := gateStats.servers
	gateStats.servers = nil
	gateStats.access.Unlock()
	if len(servers) == 0 {
		return nil
	}
	stats := make([]HandshakeGateStat, 0, len(servers))
	for _, stat := range servers {
		stats = append(stats, *stat)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Turns+stats[i].Hellos != stats[j].Turns+stats[j].Hellos {
			return stats[i].Turns+stats[i].Hellos > stats[j].Turns+stats[j].Hellos
		}
		return stats[i].Server < stats[j].Server
	})
	return stats
}

// String is the key as the stats name it.
func (k gateKey) String() string {
	if k.server.IsValid() {
		return k.server.String()
	}
	return k.host
}

// countOf is the counts of key, made on first use; gateStats.access must be held.
func countOf(key gateKey) *HandshakeGateStat {
	name := key.String()
	if name == "" {
		name = "unknown"
	}
	if gateStats.servers == nil {
		gateStats.servers = map[string]*HandshakeGateStat{}
	}
	stat := gateStats.servers[name]
	if stat == nil {
		if len(gateStats.servers) >= gateStatsMax {
			name = "other"
			if stat = gateStats.servers[name]; stat != nil {
				return stat
			}
		}
		stat = &HandshakeGateStat{Server: name}
		gateStats.servers[name] = stat
	}
	return stat
}

// countTurn counts a turn taken at key after waiting waited (0: at once), for a place in
// max_inflight (full) or for the window.
func countTurn(key gateKey, waited time.Duration, full, window bool) {
	gateStats.access.Lock()
	defer gateStats.access.Unlock()
	stat := countOf(key)
	stat.Turns++
	if waited > 0 {
		stat.Waited++
		stat.WaitTotal += waited
		stat.WaitMax = max(stat.WaitMax, waited)
		if full {
			stat.Full++
		}
		if window {
			stat.Window++
		}
	}
}

func countHello(key gateKey) {
	gateStats.access.Lock()
	defer gateStats.access.Unlock()
	countOf(key).Hellos++
}

func countConnectFailed(key gateKey) {
	gateStats.access.Lock()
	defer gateStats.access.Unlock()
	countOf(key).ConnectFailed++
}

// gateWaits follows one turn's waits until it is taken.
type gateWaits struct {
	began        time.Time
	full, window bool
}

// wait notes a wait before the turn: for a place in max_inflight (full), or for the window.
func (w *gateWaits) wait(full, window bool) {
	if w.began.IsZero() {
		w.began = time.Now()
	}
	w.full = w.full || full
	w.window = w.window || window
}

// taken counts the turn at key, with how long it waited, in the stats and in the dial's trace.
func (w *gateWaits) taken(ctx context.Context, key gateKey) {
	var waited time.Duration
	if !w.began.IsZero() {
		waited = time.Since(w.began)
	}
	countTurn(key, waited, w.full, w.window)
	if trace := dialTraceOf(ctx); trace != nil {
		trace.access.Lock()
		trace.waited += waited
		trace.access.Unlock()
	}
}

// DialTrace is what one dial did on its way to a TLS handshake (WithDialTrace). Safe for use from
// several goroutines. //H
type DialTrace struct {
	access     sync.Mutex
	waited     time.Duration
	connects   int
	connected  bool
	connectErr bool
	connect    time.Duration
	hello      bool
}

// DialTraceInfo is a copy of a DialTrace's findings.
type DialTraceInfo struct {
	Waited     time.Duration // in the gate, before the connect
	Connects   int           // TCP connects tried (0: none went through DialForHandshake)
	Connected  bool          // the last TCP connect was made
	ConnectErr bool          // a TCP connect failed
	Connect    time.Duration // the last TCP connect took
	Hello      bool          // a ClientHello went out
}

type dialTraceKey struct{}

// WithDialTrace returns ctx with trace in it: the dials for a TLS handshake under ctx (DialForHandshake,
// the TLS dialer, VLESS, XHTTP, gRPC when its dial gets ctx) record into it. //H
func WithDialTrace(ctx context.Context, trace *DialTrace) context.Context {
	return context.WithValue(ctx, dialTraceKey{}, trace)
}

func dialTraceOf(ctx context.Context) *DialTrace {
	if ctx == nil {
		return nil
	}
	trace, _ := ctx.Value(dialTraceKey{}).(*DialTrace)
	return trace
}

// Info is what the trace recorded so far.
func (t *DialTrace) Info() DialTraceInfo {
	t.access.Lock()
	defer t.access.Unlock()
	return DialTraceInfo{
		Waited: t.waited, Connects: t.connects, Connected: t.connected, ConnectErr: t.connectErr,
		Connect: t.connect, Hello: t.hello,
	}
}

// traceConnect dials destination over TCP, recording the connect in the trace of ctx.
func traceConnect(ctx context.Context, dialer N.Dialer, destination M.Socksaddr) (net.Conn, error) {
	trace := dialTraceOf(ctx)
	if trace == nil {
		return dialer.DialContext(ctx, N.NetworkTCP, destination)
	}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, destination)
	trace.access.Lock()
	trace.connects++
	trace.connect = time.Since(start)
	trace.connected = err == nil
	if err != nil {
		trace.connectErr = true
	}
	trace.access.Unlock()
	return conn, err
}

// traceHello records in the trace of ctx that a ClientHello went out.
func traceHello(ctx context.Context) {
	if trace := dialTraceOf(ctx); trace != nil {
		trace.access.Lock()
		trace.hello = true
		trace.access.Unlock()
	}
}
