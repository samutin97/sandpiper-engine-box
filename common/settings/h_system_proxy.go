package settings

import (
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
)

// DefaultSystemProxyRestoreCheckTimeout is how long the previous system proxy has to answer a TCP
// connect for its settings to be put back, when experimental.system_proxy does not say.
const DefaultSystemProxyRestoreCheckTimeout = time.Second

var systemProxyRestoreCheckTimeout atomic.Int64

func init() {
	systemProxyRestoreCheckTimeout.Store(int64(DefaultSystemProxyRestoreCheckTimeout))
}

// SetSystemProxyOptions applies experimental.system_proxy for the process; nil restores the
// defaults. The last box started sets it, as for the handshake gate.
func SetSystemProxyOptions(options *option.SystemProxyOptions) {
	timeout := DefaultSystemProxyRestoreCheckTimeout
	if options != nil && options.RestoreCheckTimeout > 0 {
		timeout = time.Duration(options.RestoreCheckTimeout)
	}
	systemProxyRestoreCheckTimeout.Store(int64(timeout))
}

func restoreCheckTimeout() time.Duration {
	return time.Duration(systemProxyRestoreCheckTimeout.Load())
}
