package relay

import (
	"net"
	"testing"
	"time"
)

// Review of the fix for finding 2 (maxQueued = 1 MiB). The OS side's prototype client
// (boot/net-proto/wisp.mjs in the network study) sends DATA packets of up to 65,536 bytes
// while it has credit, and the relay gives a credit of 128 packets. So a client that obeys
// the credit can have 8 MiB on the way. Here it sends 120 packets of 64 KiB, inside the first
// credit, to a far end that does not read yet. It broke no rule: its stream must not be
// reset for "flow control violated". (What the kernel's socket buffers take is not queued in
// the relay, which is why a small upload does not show it.)
func TestOptUploadWithinCreditIsNotReset(t *testing.T) {
	r := newRig(t)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			time.Sleep(20 * time.Second) // a far end that is slow to read
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	r.rl.Ports = append(r.rl.Ports, port)
	c := open(t, r)
	c.send(pConnect, 1, connectBody(port, "127.0.0.1"))
	c.read(t)
	part := make([]byte, 65535-5) // the rig's sender stops at a 16-bit frame length
	const packets = 120           // under the credit of 128
	go func() {
		for i := 0; i < packets; i++ {
			c.send(pData, 1, part)
		}
	}()
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		typ, id, body, ok := c.read(t) // gives up after 5 s of silence
		if !ok {
			return
		}
		if typ == pClose && id == 1 && body[0] == reasonInvalid {
			t.Fatalf("%d packets of 64 KiB, inside the credit of %d, and the stream is reset with reason %#x (flow control violated)", packets, buffer, body[0])
		}
	}
}

// Review of the fix for finding 5 in the relay (at most 10 refusals logged per user a
// minute). The safety watcher and the administrators read limit trips from the log. Ten
// refusals of another kind first (a refused port is not a limit trip) use the allowance up,
// and the limit trips that follow leave no row.
func TestOptLimitTripIsLoggedAfterOtherRefusals(t *testing.T) {
	r := newRig(t)
	r.db.Exec(`UPDATE quotas SET dests_per_min = 1 WHERE tier = 'member'`)
	second := echoServer(t)
	defer second.Close()
	port2 := second.Addr().(*net.TCPAddr).Port
	r.rl.Ports = append(r.rl.Ports, port2)
	c := open(t, r)
	for i := uint32(1); i <= 10; i++ {
		c.send(pConnect, i, connectBody(22, "127.0.0.1"))
		expectClose(t, c, i, reasonBlocked)
	}
	c.send(pConnect, 20, connectBody(r.port, "127.0.0.1"))
	c.read(t)
	c.send(pConnect, 21, connectBody(port2, "127.0.0.1")) // over the destinations limit
	expectClose(t, c, 21, reasonThrottled)
	time.Sleep(200 * time.Millisecond)
	var rows int
	r.db.QueryRow(`SELECT count(*) FROM conn_log WHERE outcome = 'too many destinations'`, &rows)
	if rows == 0 {
		t.Errorf("the user went over the destinations limit and the log has no row saying so (ten refused ports came first)")
	}
}
