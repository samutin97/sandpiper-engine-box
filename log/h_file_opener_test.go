package log

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

type recordingOpener struct {
	path   string
	buffer bytes.Buffer
	closed bool
}

func (o *recordingOpener) OpenLogFile(path string) (io.WriteCloser, error) {
	o.path = path
	return o, nil
}
func (o *recordingOpener) Write(p []byte) (int, error) { return o.buffer.Write(p) }
func (o *recordingOpener) Close() error                { o.closed = true; return nil }

// A FileOpener in the context opens the log file: the entries at the level go to it, one per
// Write, and it is closed with the factory.
func TestH_LogFileOpener(t *testing.T) {
	opener := &recordingOpener{}
	ctx := service.ContextWith[FileOpener](service.ContextWithDefaultRegistry(context.Background()), FileOpener(opener))
	path := filepath.Join(t.TempDir(), "box.log")
	factory, err := New(Options{Context: ctx, Options: option.LogOptions{Output: path, Level: "warn"}, BaseTime: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := factory.Start(); err != nil {
		t.Fatal(err)
	}
	logger := factory.NewLogger("outbound/vless[a]")
	logger.Error("open connection to 192.0.2.1:443")
	logger.Info("below the level")
	if err := factory.Close(); err != nil {
		t.Fatal(err)
	}
	if opener.path != path || !opener.closed {
		t.Fatalf("opener path %q closed %v", opener.path, opener.closed)
	}
	got := opener.buffer.String()
	if !strings.Contains(got, "open connection to 192.0.2.1:443") || strings.Contains(got, "below the level") {
		t.Fatalf("written %q", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the default file was opened too")
	}

	// without one: the file, as before
	factory, err = New(Options{Context: service.ContextWithDefaultRegistry(context.Background()), Options: option.LogOptions{Output: path}, BaseTime: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := factory.Start(); err != nil {
		t.Fatal(err)
	}
	factory.NewLogger("").Error("written to the file")
	factory.Close()
	content, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(content), "written to the file") {
		t.Fatalf("default file: %q %v", content, err)
	}
}
