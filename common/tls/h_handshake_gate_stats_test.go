package tls

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

func statOf(stats []HandshakeGateStat, server string) HandshakeGateStat {
	for _, stat := range stats {
		if stat.Server == server {
			return stat
		}
	}
	return HandshakeGateStat{}
}

// Five handshakes to one address in a row, one at a time, 40 ms apart, at most 3 in 300 ms: the
// stats count five turns and five ClientHellos there, four of them waited (the gap), at least one
// for the window, and a failed connect; the next take starts from nothing.
func TestH_HandshakeGateStatsCount(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{
		Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(40 * time.Millisecond),
		Window: badoption.Duration(300 * time.Millisecond), WindowMax: 3,
	})
	defer SetHandshakeGate(nil)
	TakeHandshakeGateStats()
	dialer := &gateDialer{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.40"), Port: 443}}
	for i := 0; i < 5; i++ {
		conn, err := DialForHandshake(context.Background(), dialer, M.ParseSocksaddr("192.0.2.40:443"))
		if err != nil {
			t.Fatal(err)
		}
		release, err := enterHandshake(context.Background(), conn, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	failing := &gateDialer{remote: dialer.remote, fail: true}
	if _, err := DialForHandshake(context.Background(), failing, M.ParseSocksaddr("192.0.2.40:443")); err == nil {
		t.Fatal("the failing dial connected")
	}
	stat := statOf(TakeHandshakeGateStats(), "192.0.2.40/32")
	if stat.Turns != 6 || stat.Hellos != 5 || stat.ConnectFailed != 1 {
		t.Fatalf("turns %d, hellos %d, failed connects %d; want 6, 5, 1", stat.Turns, stat.Hellos, stat.ConnectFailed)
	}
	if stat.Waited < 5 || stat.Window < 1 || stat.WaitMax < 30*time.Millisecond || stat.WaitTotal < stat.WaitMax {
		t.Fatalf("waits: %+v", stat)
	}
	if again := TakeHandshakeGateStats(); again != nil {
		t.Fatalf("counted again: %+v", again)
	}
}

// A turn waiting for a place in max_inflight is counted as such; a domain's first dial counts at
// the domain and at the address it reached.
func TestH_HandshakeGateStatsFullAndNames(t *testing.T) {
	SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(time.Millisecond)})
	defer SetHandshakeGate(nil)
	TakeHandshakeGateStats()
	conn := addrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.41"), Port: 443}}
	release, err := enterHandshake(context.Background(), conn, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		second, err := enterHandshake(context.Background(), conn, "example.com")
		if err != nil {
			t.Error(err)
			return
		}
		second()
	}()
	time.Sleep(50 * time.Millisecond)
	release()
	<-done
	stat := statOf(TakeHandshakeGateStats(), "192.0.2.41/32")
	if stat.Turns != 2 || stat.Waited != 1 || stat.Full != 1 || stat.WaitMax < 40*time.Millisecond {
		t.Fatalf("%+v", stat)
	}

	dialer := &gateDialer{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.42"), Port: 443}}
	named, err := DialForHandshake(context.Background(), dialer, M.ParseSocksaddr("server.example.org:443"))
	if err != nil {
		t.Fatal(err)
	}
	end, err := enterHandshake(context.Background(), named, "server.example.org")
	if err != nil {
		t.Fatal(err)
	}
	end()
	stats := TakeHandshakeGateStats()
	if statOf(stats, "server.example.org").Turns != 1 || statOf(stats, "192.0.2.42/32").Turns != 1 || statOf(stats, "192.0.2.42/32").Hellos != 1 {
		t.Fatalf("%+v", stats)
	}
}

// The trace of a dial tells a TCP connect that failed from a handshake that started, with the
// gate and without it.
func TestH_DialTrace(t *testing.T) {
	for _, gate := range []bool{true, false} {
		if gate {
			SetHandshakeGate(&option.HandshakeGateOptions{Enabled: true, MaxInflight: 1, MinGap: badoption.Duration(30 * time.Millisecond)})
		} else {
			SetHandshakeGate(nil)
		}
		remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.43"), Port: 443}
		trace := &DialTrace{}
		ctx := WithDialTrace(context.Background(), trace)
		if _, err := DialForHandshake(ctx, &gateDialer{remote: remote, fail: true}, M.ParseSocksaddr("192.0.2.43:443")); err == nil {
			t.Fatal("connected")
		}
		if info := trace.Info(); info.Connects != 1 || info.Connected || !info.ConnectErr || info.Hello {
			t.Fatalf("gate %v, failed connect: %+v", gate, info)
		}
		trace = &DialTrace{}
		ctx = WithDialTrace(context.Background(), trace)
		conn, err := DialForHandshake(ctx, &gateDialer{remote: remote}, M.ParseSocksaddr("192.0.2.43:443"))
		if err != nil {
			t.Fatal(err)
		}
		if info := trace.Info(); !info.Connected || info.Hello {
			t.Fatalf("gate %v, connected: %+v", gate, info)
		}
		release, err := enterHandshake(ctx, conn, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		release()
		info := trace.Info()
		if !info.Connected || info.ConnectErr || !info.Hello || info.Connects != 1 {
			t.Fatalf("gate %v, handshake: %+v", gate, info)
		}
		if gate && info.Waited < 20*time.Millisecond {
			t.Fatalf("the wait in the gate was not traced: %+v", info)
		}
	}
	SetHandshakeGate(nil)
	TakeHandshakeGateStats()
}
