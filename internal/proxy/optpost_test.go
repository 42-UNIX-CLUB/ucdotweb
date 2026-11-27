package proxy

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Review of the fix for finding 12 (a POST over 8 MiB is refused, not cut). The body is now
// read whole into memory before the upstream request starts, and nothing bounds how long
// that read may take: the 10-minute limit starts after it and the server has no read
// timeout. So a client that sends most of a body and then stops holds that memory for as
// long as it likes, on as many requests as the rate limit lets it open (120 a minute).
// Here 20 requests each send 4 MiB of an announced 8 MiB and then wait.
func TestOptStalledPostBodiesAreNotHeldInMemory(t *testing.T) {
	r := newRig(t, true)
	addr := r.front.Listener.Addr().String()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	const conns, sent = 20, 4 << 20
	part := []byte(strings.Repeat("x", 64<<10))
	for i := 0; i < conns; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "POST /proxy/github.com/o/r/git-upload-pack HTTP/1.1\r\nHost: x\r\nX-UCOS-Proxy: 1\r\n"+
			"Content-Type: application/x-git-upload-pack-request\r\nContent-Length: %d\r\n\r\n", 8<<20)
		for n := 0; n < sent; n += len(part) {
			if _, err := c.Write(part); err != nil {
				t.Fatalf("connection %d: %v", i, err)
			}
		}
	}
	time.Sleep(time.Second) // every request now waits for the rest of its body
	runtime.GC()
	runtime.ReadMemStats(&after)
	held := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("%d POSTs, each stopped after %d MiB of its body: heap grew by %d MiB, upstream requests made: %d", conns, sent>>20, held>>20, r.hits.Load())
	if held > 16<<20 {
		t.Errorf("%d stalled POST bodies make the proxy hold %d MiB, with no time limit on the read", conns, held>>20)
	}
}
