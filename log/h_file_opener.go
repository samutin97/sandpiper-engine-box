package log

import (
	"context"
	"io"
	"os"

	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

// FileOpener opens the log file of a box (log.output naming a file), in place of the default: the
// file opened for append, mode 0644, written as it is. An application that embeds sing-box
// registers one in the context's service registry to choose how the file is written, for
// example to rotate it at a size or to leave addresses out of the lines. Each Write gets one
// formatted entry.
type FileOpener interface {
	OpenLogFile(path string) (io.WriteCloser, error)
}

// openLogFile opens path with the context's FileOpener, or as sing-box always did.
func openLogFile(ctx context.Context, path string) (io.Writer, io.Closer, error) {
	if ctx != nil {
		if opener := service.FromContext[FileOpener](ctx); opener != nil {
			file, err := opener.OpenLogFile(path)
			if err != nil {
				return nil, nil, err
			}
			return file, file, nil
		}
	}
	file, err := filemanager.OpenFile(ctx, path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, err
	}
	return file, file, nil
}
