package relay

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/netguard"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

const origin = "https://uc.example"

type rig struct {
	srv     *httptest.Server
	db      *store.DB
	minter  *Minter
	rl      *Relay
	echo    net.Listener
	port    int
	allowed atomic.Bool
}

func echoServer(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return l
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{}
	r.allowed.Store(true)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r.minter = &Minter{Issuer: origin, Kid: "r1", Key: priv}
	v, err := NewVerifier(origin, "r1", pub)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.TempDir()+"/r.db", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	r.db = db
	r.echo = echoServer(t)
	r.port = r.echo.Addr().(*net.TCPAddr).Port
	r.rl = &Relay{Verifier: v, DB: db, Origin: origin, Guard: &netguard.Guard{AllowLoopback: true},
		Ports: []int{r.port, r.port + 1}, Recheck: 100 * time.Millisecond,
		Check: func(sub, sid string) error {
			if !r.allowed.Load() {
				return errors.New("revoked")
			}
			return nil
		}}
	r.srv = httptest.NewServer(r.rl)
	t.Cleanup(func() { r.srv.Close(); r.echo.Close(); db.Close() })
	return r
}

func (r *rig) token(t *testing.T) string {
	tok, err := r.minter.Mint("u1", "sidhash", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// client is a minimal WebSocket client: enough to speak Wisp to the relay in tests.
type client struct {
	c  net.Conn
	br *bufio.Reader
}

func dial(t *testing.T, r *rig, org, protocols string) (*client, int) {
	t.Helper()
	c, err := net.Dial("tcp", r.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	req := "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: " + org + "\r\n"
	if protocols != "" {
		req += "Sec-WebSocket-Protocol: " + protocols + "\r\n"
	}
	io.WriteString(c, req+"\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		c.Close()
		return nil, resp.StatusCode
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" || resp.Header.Get("Sec-WebSocket-Protocol") != "wisp" {
		t.Fatalf("bad handshake: %v", resp.Header)
	}
	t.Cleanup(func() { c.Close() })
	return &client{c: c, br: br}, 101
}

func (c *client) send(t byte, id uint32, payload []byte) {
	p := packet(t, id, payload)
	h := []byte{0x82}
	switch n := len(p); {
	case n < 126:
		h = append(h, 0x80|byte(n))
	default:
		h = append(h, 0x80|126, byte(n>>8), byte(n))
	}
	mask := []byte{1, 2, 3, 4}
	h = append(h, mask...)
	for i := range p {
		p[i] ^= mask[i&3]
	}
	c.c.Write(append(h, p...))
}

// read returns the next Wisp packet, or ok=false when the socket closed.
func (c *client) read(t *testing.T) (typ byte, id uint32, body []byte, ok bool) {
	c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		h := make([]byte, 2)
		if _, err := io.ReadFull(c.br, h); err != nil {
			return 0, 0, nil, false
		}
		n := int(h[1] & 0x7f)
		if n == 126 {
			b := make([]byte, 2)
			io.ReadFull(c.br, b)
			n = int(binary.BigEndian.Uint16(b))
		} else if n == 127 {
			b := make([]byte, 8)
			io.ReadFull(c.br, b)
			n = int(binary.BigEndian.Uint64(b))
		}
		p := make([]byte, n)
		io.ReadFull(c.br, p)
		if h[0]&0x0f == 8 {
			return 0, 0, nil, false
		}
		if h[0]&0x0f != 2 {
			continue
		}
		return p[0], binary.LittleEndian.Uint32(p[1:5]), p[5:], true
	}
}

func connectBody(port int, host string) []byte {
	b := []byte{1, byte(port), byte(port >> 8)}
	return append(b, host...)
}

func open(t *testing.T, r *rig) *client {
	c, code := dial(t, r, origin, "wisp, ucos-token."+r.token(t))
	if code != 101 {
		t.Fatalf("upgrade: %d", code)
	}
	if typ, id, body, _ := c.read(t); typ != pContinue || id != 0 || binary.LittleEndian.Uint32(body) != buffer {
		t.Fatalf("first packet: %d %d", typ, id)
	}
	return c
}

func TestEcho(t *testing.T) {
	r := newRig(t)
	c := open(t, r)
	c.send(pConnect, 1, connectBody(r.port, "127.0.0.1"))
	if typ, id, _, _ := c.read(t); typ != pContinue || id != 1 {
		t.Fatalf("connect: got %d on %d", typ, id)
	}
	c.send(pData, 1, []byte("hello relay"))
	var got string
	for len(got) < len("hello relay") {
		typ, id, body, ok := c.read(t)
		if !ok {
			t.Fatal("closed")
		}
		if typ == pData && id == 1 {
			got += string(body)
		}
	}
	if got != "hello relay" {
		t.Fatalf("echo %q", got)
	}
	c.send(pClose, 1, []byte{reasonVoluntary})
	c.c.Close()
	// the relay logs and flushes usage when it sees the close; wait for it, up to 5 s
	var host string
	var bytes, used int64
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		host, bytes = "", 0
		_ = r.db.QueryRow(`SELECT host, bytes FROM conn_log WHERE kind='relay'`, &host, &bytes)
		used, _, _ = r.db.UsageToday("u1", "relay")
		if host != "" && used == 22 {
			break
		}
	}
	if host != "127.0.0.1" || bytes != 22 {
		t.Fatalf("log %q %d, want host only and 22 bytes", host, bytes)
	}
	if used != 22 {
		t.Fatalf("usage %d, want 22", used)
	}
}

func TestUpgradeRefusals(t *testing.T) {
	r := newRig(t)
	expired, _ := r.minter.Mint("u1", "s", time.Now().Add(-10*time.Minute))
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := (&Minter{Issuer: origin, Kid: "r1", Key: otherPriv}).Mint("u1", "s", time.Now())
	cases := map[string]struct {
		org, protos string
		want        int
	}{
		"wrong origin":  {"https://evil.example", "wisp, ucos-token." + r.token(t), 403},
		"no token":      {origin, "wisp", 400},
		"no wisp":       {origin, "ucos-token." + r.token(t), 400},
		"expired token": {origin, "wisp, ucos-token." + expired, 401},
		"forged token":  {origin, "wisp, ucos-token." + forged, 401},
		"garbage token": {origin, "wisp, ucos-token.abc", 401},
	}
	for name, c := range cases {
		if _, code := dial(t, r, c.org, c.protos); code != c.want {
			t.Errorf("%s: %d, want %d", name, code, c.want)
		}
	}
	r.allowed.Store(false)
	if _, code := dial(t, r, origin, "wisp, ucos-token."+r.token(t)); code != 403 {
		t.Errorf("revoked: %d, want 403", code)
	}
	r.allowed.Store(true)
	r.db.SetFlag("a", "relay_off", true)
	if _, code := dial(t, r, origin, "wisp, ucos-token."+r.token(t)); code != 503 {
		t.Errorf("switched off: %d, want 503", code)
	}
}

func expectClose(t *testing.T, c *client, id uint32, reason byte) {
	t.Helper()
	for {
		typ, gid, body, ok := c.read(t)
		if !ok {
			t.Fatal("socket closed")
		}
		if typ == pClose && gid == id {
			if body[0] != reason {
				t.Fatalf("stream %d closed with %#x, want %#x", id, body[0], reason)
			}
			return
		}
	}
}

func TestStreamRefusals(t *testing.T) {
	r := newRig(t)
	c := open(t, r)
	c.send(pConnect, 1, connectBody(22, "127.0.0.1"))
	expectClose(t, c, 1, reasonBlocked) // port not allowed
	r.rl.Guard = &netguard.Guard{}      // loopback no longer allowed
	c.send(pConnect, 2, connectBody(r.port, "127.0.0.1"))
	expectClose(t, c, 2, reasonBlocked)
	c.send(pConnect, 3, connectBody(r.port, "localhost"))
	expectClose(t, c, 3, reasonBlocked)
	c.send(pConnect, 4, []byte{2, 80, 0, 'x'}) // UDP
	expectClose(t, c, 4, reasonInvalid)
}

func TestConnectionQuota(t *testing.T) {
	r := newRig(t)
	r.db.Exec(`UPDATE quotas SET conns = 1 WHERE tier = 'member'`)
	c := open(t, r)
	c.send(pConnect, 1, connectBody(r.port, "127.0.0.1"))
	c.read(t) // CONTINUE
	c.send(pConnect, 2, connectBody(r.port, "127.0.0.1"))
	expectClose(t, c, 2, reasonThrottled)
}

func TestDestinationQuota(t *testing.T) {
	r := newRig(t)
	r.db.Exec(`UPDATE quotas SET dests_per_min = 1 WHERE tier = 'member'`)
	c := open(t, r)
	c.send(pConnect, 1, connectBody(r.port, "127.0.0.1"))
	c.read(t)
	c.send(pConnect, 2, connectBody(r.port+1, "127.0.0.1")) // a second destination within a minute
	expectClose(t, c, 2, reasonThrottled)
	c.send(pConnect, 3, connectBody(r.port, "127.0.0.1")) // the same destination again is fine
	if typ, id, _, _ := c.read(t); typ != pContinue || id != 3 {
		t.Fatalf("same destination: %d on %d", typ, id)
	}
}

func TestDailyQuotaCut(t *testing.T) {
	r := newRig(t)
	r.db.Exec(`UPDATE quotas SET bytes_per_day = 10 WHERE tier = 'member'`)
	c := open(t, r)
	c.send(pConnect, 1, connectBody(r.port, "127.0.0.1"))
	c.read(t)
	c.send(pData, 1, []byte("more than ten bytes"))
	expectClose(t, c, 1, reasonThrottled)
	c.send(pConnect, 2, connectBody(r.port, "127.0.0.1"))
	expectClose(t, c, 2, reasonThrottled)
}

func TestLiveRevocationAndPanic(t *testing.T) {
	for _, how := range []string{"revoke", "panic"} {
		t.Run(how, func(t *testing.T) {
			r := newRig(t)
			c := open(t, r)
			c.send(pConnect, 1, connectBody(r.port, "127.0.0.1"))
			c.read(t)
			if how == "revoke" {
				r.allowed.Store(false)
			} else {
				r.db.SetFlag("a", "all_off", true)
			}
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if _, _, _, ok := c.read(t); !ok {
					return // the relay closed the socket
				}
			}
			t.Fatal("socket still open")
		})
	}
}

func TestFlowControlViolation(t *testing.T) {
	r := newRig(t)
	// a TCP server that never reads, so the relay's queue fills
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			time.Sleep(5 * time.Second)
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	r.rl.Ports = append(r.rl.Ports, port)
	c := open(t, r)
	c.send(pConnect, 1, connectBody(port, "127.0.0.1"))
	c.read(t)
	big := []byte(strings.Repeat("x", 60000))
	for i := 0; i < buffer*4; i++ {
		c.send(pData, 1, big)
	}
	expectClose(t, c, 1, reasonInvalid)
	_ = fmt.Sprint()
}
