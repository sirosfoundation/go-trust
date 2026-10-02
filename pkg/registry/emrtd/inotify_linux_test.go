//go:build linux

package emrtd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// kernelWatches counts the inotify watches this process holds. WatchList is
// keyed by path, so it cannot see a stale watch left on an old inode under an
// unchanged path string; the kernel's own count can.
func kernelWatches(t *testing.T) int {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	n := 0
	for _, fd := range fds {
		data, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", fd.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "inotify wd:") {
				n++
			}
		}
	}
	return n
}

// Repeated symlinked-root swaps, keeping every old tree (a rollback-friendly
// deployment), must not accumulate kernel watches on the old targets.
func TestWatch_RepeatedSymlinkSwapsDoNotLeakKernelWatches(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	base := t.TempDir()
	link := filepath.Join(base, "current")
	mk := func(i int, withAnchor bool) string {
		dir := filepath.Join(base, fmt.Sprintf("v%d", i))
		if withAnchor {
			writeAnchors(t, dir, map[string][]*node{"SWE": {csca}})
		} else {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "SWE"), 0o755))
		}
		return dir
	}
	require.NoError(t, os.Symlink(mk(0, true), link))

	before := kernelWatches(t)
	r, err := New(Config{AnchorsDir: link, Watch: true, ReloadDebounce: 20 * time.Millisecond, Logger: quietLogger(), Now: func() time.Time { return tNow }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	baseline := kernelWatches(t) - before
	require.Positive(t, baseline)

	for i := 1; i <= 6; i++ {
		withAnchor := i%2 == 0
		tmp := filepath.Join(base, "current.tmp")
		require.NoError(t, os.Symlink(mk(i, withAnchor), tmp))
		require.NoError(t, os.Rename(tmp, link))
		require.Eventually(t, func() bool {
			return eval(t, r, req("SWE", []*node{dsc}, nil)).Decision == withAnchor
		}, 5*time.Second, 20*time.Millisecond, "swap %d", i)
		require.Eventually(t, func() bool { return kernelWatches(t)-before == baseline }, 5*time.Second, 20*time.Millisecond,
			"swap %d: %d kernel watches, want %d", i, kernelWatches(t)-before, baseline)
	}
}
