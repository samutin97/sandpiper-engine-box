package awg

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestH_MaskIpcSecrets(t *testing.T) {
	ipc := "private_key=aaaa\njc=4\nheader_protection_key=bbbb\npublic_key=cccc\npreshared_key=dddd\nendpoint=192.0.2.1:51820"
	got := maskIpcSecrets(ipc)
	for _, secret := range []string{"aaaa", "bbbb", "dddd"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %s in %q", secret, got)
		}
	}
	if !strings.Contains(got, "jc=4") || !strings.Contains(got, "public_key=cccc") {
		t.Fatalf("lost the rest: %q", got)
	}
}

func TestH_KeepaliveRangeReachesTheUAPI(t *testing.T) {
	opts := option.AwgEndpointOptions{
		PrivateKey: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
		Peers: []option.AwgPeerOptions{{
			Address: "192.0.2.1", Port: 51820, PublicKey: "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=",
			PersistentKeepaliveInterval: "20-30",
		}},
	}
	ipc, err := genIpcConfig(opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ipc, "persistent_keepalive_interval=20-30") {
		t.Fatalf("ipc %q", ipc)
	}
	var r option.AwgRange
	if err := r.UnmarshalJSON([]byte("25")); err != nil || r != "25" {
		t.Fatalf("a number: %q %v", r, err)
	}
}

func TestH_KeepaliveOnUseHoldsTheKeepalive(t *testing.T) {
	opts := option.AwgEndpointOptions{
		KeepaliveOnUse: true,
		Peers: []option.AwgPeerOptions{{
			PublicKey: "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=", PersistentKeepaliveInterval: "25-35",
		}},
	}
	held := holdKeepalives(&opts)
	if held == nil || opts.Peers[0].PersistentKeepaliveInterval != "" {
		t.Fatalf("not held: %+v", opts.Peers[0])
	}
	if !strings.Contains(held.lines, "update_only=true\npersistent_keepalive_interval=25-35") || !strings.HasPrefix(held.lines, "public_key=6262") {
		t.Fatalf("lines %q", held.lines)
	}
	opts.KeepaliveOnUse = false
	opts.Peers[0].PersistentKeepaliveInterval = "25"
	if holdKeepalives(&opts) != nil || opts.Peers[0].PersistentKeepaliveInterval != "25" {
		t.Fatal("held without keepalive_on_use")
	}
}

func TestH_CheckIpcValues(t *testing.T) {
	base := option.AwgEndpointOptions{PrivateKey: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=", Peers: []option.AwgPeerOptions{{Address: "192.0.2.1", Port: 1, PublicKey: "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="}}}
	bad := []func(o *option.AwgEndpointOptions){
		func(o *option.AwgEndpointOptions) { o.Awg.I1 = "<b 0x01>\nprivate_key=x" },
		func(o *option.AwgEndpointOptions) { o.Awg.Jc = 100000; o.Awg.Jmax = 10 },
		func(o *option.AwgEndpointOptions) { o.Awg.Jc = 1; o.Awg.Jmin = 60; o.Awg.Jmax = 50 },
		func(o *option.AwgEndpointOptions) { o.Awg.S1 = -1 },
		func(o *option.AwgEndpointOptions) { o.Peers[0].PersistentKeepaliveInterval = "25\nendpoint=1.1.1.1:1" },
	}
	for i, mutate := range bad {
		o := base
		o.Peers = append([]option.AwgPeerOptions(nil), base.Peers...)
		mutate(&o)
		if _, err := genIpcConfig(o, nil); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	if _, err := genIpcConfig(base, nil); err != nil {
		t.Fatal(err)
	}
}
