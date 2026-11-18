package box

import (
	"github.com/sagernet/sing-box/common/settings"
	"github.com/sagernet/sing-box/option"
)

// hSetSystemProxyOptions applies experimental.system_proxy for the process, as the handshake gate
// is applied: the last box started sets it.
func hSetSystemProxyOptions(experimentalOptions option.ExperimentalOptions) {
	settings.SetSystemProxyOptions(experimentalOptions.SystemProxy)
}
