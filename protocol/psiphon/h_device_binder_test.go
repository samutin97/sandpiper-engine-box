package psiphon

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

type binderPlatform struct {
	adapter.PlatformInterface
	use       bool
	protected []int
}

func (p *binderPlatform) UsePlatformAutoDetectInterfaceControl() bool { return p.use }
func (p *binderPlatform) AutoDetectInterfaceControl(fd int) error {
	p.protected = append(p.protected, fd)
	return nil
}

func TestH_PsiphonSocketsAreProtected(t *testing.T) {
	platform := &binderPlatform{use: true}
	binder := deviceBinderFor(platform)
	if binder == nil {
		t.Fatal("no binder with a protecting platform")
	}
	if _, err := binder.BindToDevice(42); err != nil || len(platform.protected) != 1 || platform.protected[0] != 42 {
		t.Fatalf("%v %v", err, platform.protected)
	}
	if deviceBinderFor(&binderPlatform{use: false}) != nil || deviceBinderFor(nil) != nil {
		t.Fatal("a binder without a protecting platform")
	}
}
