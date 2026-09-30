//go:build unix

package emrtd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A FIFO named like an anchor or CRL must be refused, not read: reading it
// would block startup (or a reload) forever.
func TestSpecialFilesRefusedNotRead(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	for _, tc := range []struct{ name, dir, file string }{
		{"anchor", "anchors", "evil.pem"},
		{"crl", "crls", "evil.crl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			anchors, crls := filepath.Join(root, "anchors"), filepath.Join(root, "crls")
			writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
			require.NoError(t, os.MkdirAll(filepath.Join(crls, "SWE"), 0o755))
			require.NoError(t, syscall.Mkfifo(filepath.Join(root, tc.dir, "SWE", tc.file), 0o644))

			done := make(chan error, 1)
			go func() {
				_, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
				done <- err
			}()
			select {
			case err := <-done:
				require.Error(t, err)
				assert.Contains(t, err.Error(), "regular file")
			case <-time.After(5 * time.Second):
				t.Fatal("loading blocked on a FIFO")
			}
		})
	}
}
