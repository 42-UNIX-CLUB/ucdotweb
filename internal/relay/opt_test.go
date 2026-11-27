package relay

import (
	"encoding/binary"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func (r *rig) waitNoSockets(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		r.rl.mu.Lock()
		n := 0
		for _, us := range r.rl.users {
			n += us.refs
		}
		r.rl.mu.Unlock()
		if n == 0 {
			return
		}
	}
	t.Fatal("the user's socket is still open")
}

// Finding L7: the count of new destinations per minute lives in the user's state, which is
// dropped when the user's last socket closes. Closing the socket and opening a new one (the
// same 5-minute token works again) gives a fresh allowance at once.
func TestOptDestinationQuotaSurvivesReconnect(t *testing.T) {
	r := newRig(t)
	second := echoServer(t) // a second destination that answers, so "let through" shows as CONTINUE
	defer second.Close()
	port2 := second.Addr().(*net.TCPAddr).Port
	r.rl.Ports = append(r.rl.Ports, port2)
	r.db.Exec(`UPDATE quotas SET dests_per_min = 1 WHERE tier = 'member'`)
	tok := r.token(t)
	c, code := dial(t, r, origin, "wisp, ucos-token."+tok)
	if code != 101 {
		t.Fatalf("upgrade: %d", code)
	}
	c.read(t) // CONTINUE on stream 0
	c.send(pConnect, 1, connectBody(r.port, "127.0.0.1"))
	c.read(t)
	c.send(pConnect, 2, connectBody(port2, "127.0.0.1"))
	expectClose(t, c, 2, reasonThrottled) // the limit works inside one socket
	c.c.Close()
	r.waitNoSockets(t)

	c2, code := dial(t, r, origin, "wisp, ucos-token."+tok) // the same token, seconds later
	if code != 101 {
		t.Fatalf("second upgrade: %d", code)
	}
	c2.read(t)
	c2.send(pConnect, 1, connectBody(port2, "127.0.0.1")) // the second destination, within the same minute
	typ, id, body, ok := c2.read(t)
	if !ok {
		t.Fatal("socket closed")
	}
	if typ == pClose && id == 1 && body[0] == reasonThrottled {
		return // the limit held across the reconnect
	}
	t.Errorf("after a reconnect the second destination got packet type %d on stream %d (3 is CONTINUE: connected), want CLOSE with reason %#x", typ, id, reasonThrottled)
}

// sendBig sends one DATA packet in a frame with a 64-bit length (the rig's send stops at 64 KiB).
func (c *client) sendBig(id uint32, payload []byte) error {
	p := packet(pData, id, payload)
	h := []byte{0x82, 0x80 | 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} // zero mask: payload unchanged
	binary.BigEndian.PutUint64(h[2:10], uint64(len(p)))
	if _, err := c.c.Write(h); err != nil {
		return err
	}
	_, err := c.c.Write(p)
	return err
}

// Finding L4: flow control counts packets, not bytes, and a packet may be 1 MiB. One stream
// to a server that never reads makes the relay hold about 128 MiB without breaking any rule.
func TestOptQueuedBytesPerStream(t *testing.T) {
	r := newRig(t)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			time.Sleep(20 * time.Second) // never reads
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	r.rl.Ports = append(r.rl.Ports, port)
	c := open(t, r)
	c.send(pConnect, 1, connectBody(port, "127.0.0.1"))
	c.read(t)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	big := make([]byte, 1<<20-5) // the largest message the WebSocket layer accepts, with the 5-byte header
	sent := 0
	for i := 0; i < buffer; i++ { // exactly the credit the relay gave: no violation
		if err := c.sendBig(1, big); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		sent++
	}
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	runtime.ReadMemStats(&after)
	r.rl.mu.Lock()
	streams := 0
	if us := r.rl.users["u1"]; us != nil {
		streams = us.streams
	}
	r.rl.mu.Unlock()
	held := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("sent %d packets of %d bytes within the credit; stream still open: %v; heap grew by %d MiB", sent, len(big), streams == 1, held>>20)
	if streams == 1 && held > 16<<20 {
		t.Errorf("one stream within its flow control credit makes the relay hold %d MiB", held>>20)
	}
}

// Finding L3: a CLOSE that arrives while the dial is still running. closeStream reads st.conn
// (nil), then dial stores the new connection and keeps it: the TCP connection stays open and
// the user's slot is already free. Run with -race for the unsynchronised st.conn.
func TestOptCloseDuringDial(t *testing.T) {
	r := newRig(t)
	var open atomic.Int64
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			open.Add(1)
			go func() { b := make([]byte, 1); c.Read(b); open.Add(-1); c.Close() }() // counts until the relay closes its end
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	r.rl.Ports = append(r.rl.Ports, port)
	r.db.Exec(`UPDATE quotas SET conns = 0 WHERE tier = 'member'`)
	c := open0(t, r)
	const rounds = 2000
	go func() { // drain what the relay sends
		for {
			if _, _, _, ok := c.read(t); !ok {
				return
			}
		}
	}()
	for i := uint32(1); i <= rounds; i++ {
		c.send(pConnect, i, connectBody(port, "127.0.0.1"))
		c.send(pClose, i, []byte{reasonVoluntary})
	}
	time.Sleep(2 * time.Second)
	r.rl.mu.Lock()
	streams := -1
	if us := r.rl.users["u1"]; us != nil {
		streams = us.streams
	}
	r.rl.mu.Unlock()
	t.Logf("%d CONNECT+CLOSE pairs: the relay counts %d open streams, the far end still sees %d connections open", rounds, streams, open.Load())
	if streams == 0 && open.Load() > 0 {
		t.Errorf("%d upstream connections are still open although the relay counts no stream", open.Load())
	}
}

func open0(t *testing.T, r *rig) *client {
	c, code := dial(t, r, origin, "wisp, ucos-token."+r.token(t))
	if code != 101 {
		t.Fatalf("upgrade: %d", code)
	}
	c.read(t)
	return c
}

// The state kept for recent destinations is dropped once they are a minute old.
func TestUserStateIdle(t *testing.T) {
	now := time.Now()
	us := &userState{dests: map[string]time.Time{"a:80": now.Add(-30 * time.Second)}}
	if us.idle(now) {
		t.Fatal("a destination 30 s old must keep the state")
	}
	us.dests["a:80"] = now.Add(-61 * time.Second)
	if !us.idle(now) {
		t.Fatal("destinations over a minute old must not keep the state")
	}
	us.refs = 1
	if us.idle(now) {
		t.Fatal("an open socket must keep the state")
	}
}

// FlushAll writes the usage of open sockets that the 10-second flush has not written yet.
func TestFlushAllWritesPendingUsage(t *testing.T) {
	r := newRig(t)
	us := r.rl.acquire("u9")
	r.rl.account(us, 1234, 0)
	r.rl.FlushAll()
	if b, _, _ := r.db.UsageToday("u9", "relay"); b != 1234 {
		t.Fatalf("usage after FlushAll: %d, want 1234", b)
	}
	r.rl.release("u9")
}

// streams_per_min counts every stream, the same destination included, and holds across a
// reconnect.
func TestStreamsPerMinute(t *testing.T) {
	r := newRig(t)
	r.db.Exec(`UPDATE quotas SET streams_per_min = 3 WHERE tier = 'member'`)
	tok := r.token(t)
	c, code := dial(t, r, origin, "wisp, ucos-token."+tok)
	if code != 101 {
		t.Fatalf("upgrade: %d", code)
	}
	c.read(t)
	for i := uint32(1); i <= 3; i++ {
		c.send(pConnect, i, connectBody(r.port, "127.0.0.1"))
		if typ, id, _, _ := c.read(t); typ != pContinue || id != i {
			t.Fatalf("stream %d: packet %d on %d", i, typ, id)
		}
		c.send(pClose, i, []byte{reasonVoluntary})
	}
	c.send(pConnect, 4, connectBody(r.port, "127.0.0.1"))
	expectClose(t, c, 4, reasonThrottled)
	c.c.Close()
	r.waitNoSockets(t)
	c2, code := dial(t, r, origin, "wisp, ucos-token."+tok)
	if code != 101 {
		t.Fatalf("second upgrade: %d", code)
	}
	c2.read(t)
	c2.send(pConnect, 1, connectBody(r.port, "127.0.0.1"))
	expectClose(t, c2, 1, reasonThrottled)
}
