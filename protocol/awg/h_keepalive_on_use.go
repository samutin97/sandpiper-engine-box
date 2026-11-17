package awg

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/option"
)

// keepaliveOnUse holds back the peers' persistent keepalive until the endpoint is first used
// (keepalive_on_use). With it set from the start, the device sends a keepalive, so a handshake, to
// every peer as it comes up: an endpoint of the profile that nobody selected handshakes with its
// server at every start and keeps a UDP flow to it every few seconds, beside the proxy in use. //H
type keepaliveOnUse struct {
	once  sync.Once
	lines string // the UAPI lines that set the keepalives, applied at the first use
}

// holdKeepalives takes the keepalives out of the options of an endpoint with keepalive_on_use, and
// returns the UAPI lines that set them later. //H
func holdKeepalives(options *option.AwgEndpointOptions) *keepaliveOnUse {
	if !options.KeepaliveOnUse {
		return nil
	}
	var lines strings.Builder
	peers := make([]option.AwgPeerOptions, len(options.Peers))
	copy(peers, options.Peers)
	for i := range peers {
		keepalive := strings.TrimSpace(string(peers[i].PersistentKeepaliveInterval))
		if keepalive == "" || keepalive == "0" {
			continue
		}
		key, err := base64.StdEncoding.DecodeString(peers[i].PublicKey)
		if err != nil {
			continue // genIpcConfig reports the key
		}
		lines.WriteString("public_key=" + hex.EncodeToString(key) + "\nupdate_only=true\npersistent_keepalive_interval=" + keepalive + "\n")
		peers[i].PersistentKeepaliveInterval = ""
	}
	options.Peers = peers
	if lines.Len() == 0 {
		return nil
	}
	return &keepaliveOnUse{lines: strings.TrimSuffix(lines.String(), "\n")}
}

// useKeepalives sets the held keepalives, once, when the endpoint carries its first connection or
// test. //H
func (e *Endpoint) useKeepalives() {
	if e.keepalives == nil {
		return
	}
	e.keepalives.once.Do(func() {
		if err := e.Device.IpcSet(e.keepalives.lines); err != nil {
			e.logger.Warn("set the keepalive at first use: ", err)
		}
	})
}
