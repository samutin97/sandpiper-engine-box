package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestH_UserIDRange(t *testing.T) {
	item, err := NewUserIDRangeItem([]string{"0:2147483647"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		owner *adapter.ConnectionOwner
		want  bool
	}{
		{nil, false}, // no lookup or a failed one
		{&adapter.ConnectionOwner{UserId: -1}, false}, // Android INVALID_UID
		{&adapter.ConnectionOwner{UserId: 0}, true},   // root (netd)
		{&adapter.ConnectionOwner{UserId: 1051}, true},
		{&adapter.ConnectionOwner{UserId: 10123, PackageNames: []string{"a.b"}}, true},
	}
	for _, c := range cases {
		if got := item.Match(&adapter.InboundContext{ProcessInfo: c.owner}); got != c.want {
			t.Fatalf("%+v: %v", c.owner, got)
		}
	}
	if _, err := NewUserIDRangeItem([]string{"5:1"}); err == nil {
		t.Fatal("reversed range accepted")
	}
	one, _ := NewUserIDRangeItem([]string{"1000"})
	if !one.Match(&adapter.InboundContext{ProcessInfo: &adapter.ConnectionOwner{UserId: 1000}}) {
		t.Fatal("single id")
	}
}
