package awg

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// ipcSecretKeys are the UAPI keys whose values never go to the log. //H
var ipcSecretKeys = []string{"private_key=", "preshared_key=", "header_protection_key="}

// maskIpcSecrets is the UAPI config with its keys hidden, for the log: the debug log reaches the
// app's log screen and the reports users send. //H
func maskIpcSecrets(ipc string) string {
	lines := strings.Split(ipc, "\n")
	for i, line := range lines {
		for _, key := range ipcSecretKeys {
			if strings.HasPrefix(line, key) {
				lines[i] = key + "<hidden>"
			}
		}
	}
	return strings.Join(lines, "\n")
}

// checkIpcValues refuses what the UAPI text cannot carry or the device cannot take: a line break
// in a value (it would add UAPI lines of its own), jc above 128, jmin above jmax, a junk packet
// above 65507 bytes, a padding above 65535 (HC-21: these panicked the core or allocated
// gigabytes per packet). //H
func checkIpcValues(opts option.AwgEndpointOptions) error {
	a := opts.Awg
	values := []string{opts.PrivateKey, a.H1, a.H2, a.H3, a.H4, a.I1, a.I2, a.I3, a.I4, a.I5, a.HeaderProtectionKey,
		string(a.ContentPaddingAddition), string(a.RekeyAfterTime), string(a.RekeyTimeout), string(a.RejectAfterTime),
		string(a.KeepaliveTimeout), string(a.MaxHandshakeAttempts), a.IP, a.ID, a.IB}
	for _, peer := range opts.Peers {
		values = append(values, peer.PublicKey, peer.PresharedKey, peer.Address, string(peer.PersistentKeepaliveInterval))
	}
	for _, value := range values {
		if strings.ContainsAny(value, "\r\n") {
			return E.New("awg: a value has a line break")
		}
	}
	switch {
	case a.Jc < 0 || a.Jc > 128:
		return E.New("awg: jc ", a.Jc, " out of 0-128")
	case a.Jmin < 0 || a.Jmax < 0 || a.Jmax > 65507 || a.Jc > 0 && a.Jmin > a.Jmax:
		return E.New("awg: jmin ", a.Jmin, " / jmax ", a.Jmax, ": want 0 <= jmin <= jmax <= 65507")
	}
	for _, s := range []int{a.S1, a.S2, a.S3, a.S4} {
		if s < 0 || s > 65535 {
			return E.New("awg: s1-s4 out of 0-65535")
		}
	}
	return nil
}
