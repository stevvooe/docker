// +build windows

package windows

import (
	"io"

	"github.com/Sirupsen/logrus"
)

// stdinCopy asynchronously copies an io.Reader to the container's process's stdin pipe
// and closes the pipe when there is no more data to copy.
func stdinCopy(pipe io.WriteCloser, copyfrom io.Reader) {

	// Anything that comes from the client stdin should be copied
	// across to the stdin named pipe of the container.
	if copyfrom != nil {
		go func() {
			defer pipe.Close()
			logrus.Debugln("Calling io.Copy on stdin")
			bytes, err := io.Copy(pipe, copyfrom)
			logrus.Debugf("Finished io.Copy on stdin bytes=%d err=%s", bytes, err)
		}()
	} else {
		defer pipe.Close()
	}
}

// stdouterrCopy asynchronously copies data from the container's process's stdout or
// stderr pipe to an io.Writer and closes the pipe when there is no more data to
// copy.
func stdouterrCopy(pipe io.ReadCloser, pipeName string, copyto io.Writer) {
	// Anything that comes from the container named pipe stdout/err should be copied
	// across to the stdout/err of the client
	if copyto != nil {
		go func() {
			defer pipe.Close()
			logrus.Debugln("Calling io.Copy on", pipeName)
			bytes, err := io.Copy(copyto, pipe)
			logrus.Debugf("Copied %d bytes from %s", bytes, pipeName)
			if err != nil {
				// Not fatal, just debug log it
				logrus.Debugf("Error hit during copy %s", err)
			}
		}()
	} else {
		defer pipe.Close()
	}
}
