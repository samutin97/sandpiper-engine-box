package dialer

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
)

// The Android path: auto_detect_interface on, a platform with its own network interfaces and the
// protect control (VpnService.protect). Every socket of the default dialer, TCP and UDP, must
// pass through that control, or the sockets that carry the tunnel go back into it. //H

type protectNetworkManager struct {
	adapter.NetworkManager
	protected *atomic.Int32
}

func (m protectNetworkManager) AutoDetectInterface() bool { return true }
func (m protectNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}
func (m protectNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}
func (m protectNetworkManager) AutoRedirectOutputMarkFunc() control.Func { return nil }
func (m protectNetworkManager) ProtectFunc() control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		return control.Raw(conn, func(fd uintptr) error {
			if fd > 0 {
				m.protected.Add(1)
			}
			return nil
		})
	}
}

type protectPlatform struct{ adapter.PlatformInterface }

func (protectPlatform) UsePlatformNetworkInterfaces() bool { return true }

func TestH_DefaultDialerProtectsEverySocket(t *testing.T) {
	var protected atomic.Int32
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.NetworkManager](ctx, protectNetworkManager{protected: &protected})
	service.MustRegister[adapter.PlatformInterface](ctx, protectPlatform{})
	d, err := NewDefault(ctx, option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if d.networkStrategy == nil {
		t.Fatal("no network strategy: the sockets are not bound to the underlying network")
	}

	// TCP: the control of the dialer
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tcpDialer := d.dialer4.Dialer
	conn, err := tcpDialer.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if protected.Load() != 1 {
		t.Fatalf("TCP socket not protected (%d)", protected.Load())
	}

	// UDP (hysteria2, tuic, QUIC, WireGuard and AmneziaWG binds): the listen config and the UDP dialer
	packetConn, err := d.udpListener.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packetConn.Close()
	udpConn, err := d.udpDialer4.Dial("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	udpConn.Close()
	if protected.Load() != 3 {
		t.Fatalf("UDP sockets not protected (%d of 3)", protected.Load())
	}
}

// Without auto_detect_interface (what hiddify-core used to set on Android) nothing is protected:
// the app had to keep itself out of its own VPN. //H
func TestH_NoProtectWithoutAutoDetect(t *testing.T) {
	var protected atomic.Int32
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.NetworkManager](ctx, noAutoDetect{protectNetworkManager{protected: &protected}})
	service.MustRegister[adapter.PlatformInterface](ctx, protectPlatform{})
	d, err := NewDefault(ctx, option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := d.udpListener.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packetConn.Close()
	if protected.Load() != 0 {
		t.Fatal("protected without auto_detect_interface")
	}
}

type noAutoDetect struct{ protectNetworkManager }

func (noAutoDetect) AutoDetectInterface() bool { return false }
