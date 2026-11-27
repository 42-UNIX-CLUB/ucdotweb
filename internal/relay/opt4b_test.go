package relay

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Second read of the relay (cc99f77). Nothing limits how many streams a member may open in a
// minute: the three limits are streams at once, new destinations a minute and bytes a day,
// and opening the same destination again is free. Every stream that ends writes a log row
// and a usage update, and every stream that is let through makes a real TCP connection from
// the server's address. The allowance for logged refusals does not cover these: they end in
// closeStream, not in refuse.
func TestOptStreamsPerMinuteAreBounded(t *testing.T) {
	r := newRig(t)
	var accepted atomic.Int64
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	r.rl.Ports = append(r.rl.Ports, port)
	c := open(t, r)
	go func() {
		for {
			if _, _, _, ok := c.read(t); !ok {
				return
			}
		}
	}()
	const rounds = 1000
	t0 := time.Now()
	for i := uint32(1); i <= rounds; i++ { // one destination, opened again and again, 8 at a time at most
		c.send(pConnect, i, connectBody(port, "127.0.0.1"))
		if i%8 == 0 {
			time.Sleep(2 * time.Millisecond) // let the far end close them, as a real one would after its answer
		}
	}
	time.Sleep(500 * time.Millisecond)
	var rows int
	r.db.QueryRow(`SELECT count(*) FROM conn_log WHERE kind = 'relay'`, &rows)
	t.Logf("%d CONNECTs to one destination in %v: %d TCP connections made to it, %d log rows", rounds, time.Since(t0).Round(time.Millisecond), accepted.Load(), rows)
	if accepted.Load() > 200 {
		t.Errorf("one member made %d connections to one destination in under a second, with no limit on streams a minute", accepted.Load())
	}
}
