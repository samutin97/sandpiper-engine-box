package tls

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
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
	// another server name is another counter: no wait
	start := time.Now()
	release, _ := enterHandshake(context.Background(), conn, "other.example.com")
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
