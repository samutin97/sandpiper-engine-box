//go:build with_pprof

// H: pprof (and its registration on http.DefaultServeMux) only in a debug build: a release
// library must not carry a heap-dump server any caller could start.

package libbox

import (
	"net"
	"net/http"
	_ "net/http/pprof"
	"strconv"
)

type PProfServer struct {
	server *http.Server
}

func NewPProfServer(port int) *PProfServer {
	return &PProfServer{
		&http.Server{
			Addr: ":" + strconv.Itoa(port),
		},
	}
}

func (s *PProfServer) Start() error {
	ln, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return err
	}
	go s.server.Serve(ln)
	return nil
}

func (s *PProfServer) Close() error {
	return s.server.Close()
}
