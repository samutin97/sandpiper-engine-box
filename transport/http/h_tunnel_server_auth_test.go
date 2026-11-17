package http

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/sagernet/sing/common/auth"
)

// The HTTP side of a mixed or http inbound wrote the user name a client sent into the error of
// a failed authentication, and so into the log and the problem reports: half of the local proxy's
// credentials, which do not change between launches. The error now says only that it failed.
func TestH_FailedAuthenticationKeepsTheUserNameOutOfTheError(t *testing.T) {
	server := &Server{authenticator: auth.NewAuthenticator([]auth.User{{Username: "proxyuser", Password: "right"}})}
	for _, credentials := range []string{"proxyuser:wrong", "otheruser:right", "otheruser:wrong"} {
		request, _ := http.NewRequest(http.MethodConnect, "http://example.com:443", nil)
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
		_, err := server.authenticate(context.Background(), request, "Proxy-Authorization")
		if err == nil {
			t.Fatalf("%s: no error", credentials)
		}
		for _, secret := range []string{"proxyuser", "otheruser", "wrong", "right"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("%s: the error %q holds %q", credentials, err, secret)
			}
		}
	}
	request, _ := http.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("proxyuser:right")))
	if _, err := server.authenticate(context.Background(), request, "Proxy-Authorization"); err != nil {
		t.Fatalf("the right credentials: %v", err)
	}
}
