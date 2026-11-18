package settings

import (
	"context"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
)

type WindowsSystemProxy struct {
	serverAddr   M.Socksaddr
	supportSOCKS bool
	bypassDomain []string
	isEnabled    bool
	previous     *windowsProxySettings //H: the settings Enable replaced, see h_proxy_previous_windows.go
}

func NewSystemProxy(ctx context.Context, serverAddr M.Socksaddr, supportSOCKS bool, bypassDomain []string) (*WindowsSystemProxy, error) {
	return &WindowsSystemProxy{
		serverAddr:   serverAddr,
		supportSOCKS: supportSOCKS,
		bypassDomain: bypassDomain,
	}, nil
}

func (p *WindowsSystemProxy) IsEnabled() bool {
	return p.isEnabled
}

func (p *WindowsSystemProxy) Enable() error {
	p.previous = rememberPrevious(p.serverAddr)                                                 //H
	err := windowsProxy.Set("http://"+p.serverAddr.String(), strings.Join(p.bypassDomain, ";")) //H
	if err != nil {
		return err
	}
	p.isEnabled = true
	return nil
}

func (p *WindowsSystemProxy) Close() error {
	return nil
}

func (p *WindowsSystemProxy) Disable() error {
	err := p.restorePrevious() //H: back to the settings Enable replaced, or off
	if err != nil {
		return err
	}
	p.isEnabled = false
	return nil
}
