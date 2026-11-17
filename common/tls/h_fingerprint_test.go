package tls

import (
	"testing"

	utls "github.com/metacubex/utls"
)

func TestH_FingerprintNames(t *testing.T) {
	for _, name := range []string{"none", "edge", "360", "qq", ""} {
		id, err := uTLSClientHelloID(name)
		if err != nil || id != hChromeFingerprint {
			t.Fatalf("%q: %v %v", name, id, err)
		}
	}
	if id, _ := uTLSClientHelloID("ios"); id != utls.HelloSafari_Auto {
		t.Fatalf("ios: %v", id)
	}
	if id, _ := uTLSClientHelloID("firefox"); id != utls.HelloFirefox_Auto {
		t.Fatalf("firefox: %v", id)
	}
	if randomFingerprint == utls.HelloEdge_Auto || randomFingerprint == utls.HelloIOS_Auto {
		t.Fatalf("random picked an old hello: %v", randomFingerprint)
	}
}
