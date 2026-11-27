package proxy

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// Review of fef94fc: the cap of 8 running proxy requests, end to end. Eight POSTs that stop
// in the middle of their body hold the eight places. The ninth request is refused with 429
// and the word "busy". When the eight clients go away, the places come back.
func TestOptRunningCapEndToEnd(t *testing.T) {
	r := newRig(t, true)
	p := r.front.Config.Handler.(*Proxy)
	running := func() int {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.running["u1"]
	}
	addr := r.front.Listener.Addr().String()
	var held []net.Conn
	t.Cleanup(func() { // before the rig's own cleanup, which waits for running requests
		for _, c := range held {
			c.Close()
		}
	})
	for i := 0; i < maxRunning; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
		fmt.Fprintf(c, "POST /proxy/github.com/o/r/git-upload-pack HTTP/1.1\r\nHost: x\r\nX-UCOS-Proxy: 1\r\n"+
			"Content-Type: application/x-git-upload-pack-request\r\nContent-Length: %d\r\n\r\n%s", 1<<20, "0000")
	}
	for t0 := time.Now(); running() < maxRunning; time.Sleep(10 * time.Millisecond) {
		if time.Since(t0) > 5*time.Second {
			t.Fatalf("only %d of %d requests running after 5 s", running(), maxRunning)
		}
	}
	const path = "/proxy/deb.debian.org/debian/dists/stable/InRelease"
	resp := r.get(t, path, true)
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get(RefusedHeader) != "busy" {
		t.Fatalf("ninth request while eight run: %d %q, want 429 busy", resp.StatusCode, resp.Header.Get(RefusedHeader))
	}
	var rows int
	r.db.QueryRow(`SELECT count(*) FROM conn_log WHERE outcome = 'too many at once'`, &rows)
	if rows != 1 {
		t.Errorf("%d log rows 'too many at once', want 1", rows)
	}
	for _, c := range held {
		c.Close()
	}
	t0 := time.Now()
	for running() > 0 {
		if time.Since(t0) > 5*time.Second {
			t.Fatalf("5 s after the eight clients left, %d places are still taken", running())
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("all places free %v after the eight clients left", time.Since(t0).Round(time.Millisecond))
	resp = r.get(t, path, true)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("request after the places came back: %d", resp.StatusCode)
	}
}
