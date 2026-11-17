package tls

import (
	utls "github.com/metacubex/utls"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// setUTLSKeyShare reads utls.key_share of a TLS client that is not REALITY: "" or "hybrid" (the
// fingerprint's own key shares, X25519MLKEM768 included in the modern ones), or "classical"
// (without X25519MLKEM768: a ClientHello of one segment instead of two, which some DPIs cut, M4).
// REALITY has its own key_share (reality.key_share). //H
func setUTLSKeyShare(config *UTLSClientConfig, options option.OutboundTLSOptions) error {
	if options.UTLS == nil || options.Reality != nil && options.Reality.Enabled {
		return nil
	}
	switch options.UTLS.KeyShare {
	case "", "hybrid":
	case "classical":
		config.classical = true
	default:
		return E.New("unknown utls key_share: ", options.UTLS.KeyShare, ` (expected "hybrid" or "classical")`)
	}
	return nil
}

// removeHybridKeyShareForClient is removeHybridKeyShare for a plain TLS client: the classical
// shares also lose the marker that makes them reuse the hybrid share's key (Firefox), which
// would fail without it. //H
func removeHybridKeyShareForClient(spec *utls.ClientHelloSpec) {
	removeHybridKeyShare(spec)
	for _, extension := range spec.Extensions {
		if keyShares, ok := extension.(*utls.KeyShareExtension); ok {
			for i := range keyShares.KeyShares {
				if keyShares.KeyShares[i].Group != utls.GREASE_PLACEHOLDER {
					keyShares.KeyShares[i].Data = nil
				}
			}
		}
	}
}
