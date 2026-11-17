package psiphon

import (
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/sagernet/sing-box/adapter"
)

// platformDeviceBinder protects Psiphon's own sockets with the platform (VpnService.protect on
// Android), as the dialers of the other outbounds are: Psiphon dials its servers itself, and with
// the app inside its own VPN those sockets would go into the tunnel. //H
type platformDeviceBinder struct {
	platform adapter.PlatformInterface
}

func (b platformDeviceBinder) BindToDevice(fd int) (string, error) {
	return "", b.platform.AutoDetectInterfaceControl(fd)
}

// deviceBinderFor is the binder of a platform that protects sockets, or nil. //H
func deviceBinderFor(platform adapter.PlatformInterface) psiphon.DeviceBinder {
	if platform == nil || !platform.UsePlatformAutoDetectInterfaceControl() {
		return nil
	}
	return platformDeviceBinder{platform}
}
