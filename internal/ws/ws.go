// Package ws is a small WebSocket server (RFC 6455): the upgrade handshake, reading masked
// client frames (with fragmentation and control frames), and writing unmasked binary frames.
// Only what the relay needs: no extensions, no compression. Text frames are refused.
package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Conn is an upgraded connection.
type Conn struct {
	c        net.Conn
	r        *bufio.Reader
	wmu      sync.Mutex
	MaxFrame int // largest message accepted from the client
}

// Upgrade completes the handshake. protocol is the subprotocol to echo ("" for none).
func Upgrade(w http.ResponseWriter, r *http.Request, protocol string) (*Conn, error) {
	if r.Method != "GET" || !headerHas(r.Header, "Connection", "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "WebSocket upgrade expected.", http.StatusBadRequest)
		return nil, errors.New("ws: not an upgrade")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "Unsupported WebSocket version.", http.StatusUpgradeRequired)
		return nil, errors.New("ws: bad version")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if k, err := base64.StdEncoding.DecodeString(key); err != nil || len(k) != 16 {
		http.Error(w, "Bad WebSocket key.", http.StatusBadRequest)
		return nil, errors.New("ws: bad key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Upgrade not possible.", http.StatusInternalServerError)
		return nil, errors.New("ws: cannot hijack")
	}
	c, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(key + guid))
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(sum[:]) + "\r\n"
	if protocol != "" {
		resp += "Sec-WebSocket-Protocol: " + protocol + "\r\n"
	}
	resp += "\r\n"
	c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(resp)); err != nil {
		c.Close()
		return nil, err
	}
	c.SetWriteDeadline(time.Time{})
	return &Conn{c: c, r: rw.Reader, MaxFrame: 1 << 20}, nil
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), token) {
				return true
			}
		}
	}
	return false
}

// Protocols returns the subprotocols the client offered.
func Protocols(r *http.Request) []string {
	var out []string
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// ErrClosed is returned after the peer closed.
var ErrClosed = errors.New("ws: closed")

// Read returns the next binary message, answering pings and handling close.
func (c *Conn) Read() ([]byte, error) {
	var msg []byte
	started := false
	for {
		var h [2]byte
		if _, err := io.ReadFull(c.r, h[:]); err != nil {
			return nil, err
		}
		fin, op := h[0]&0x80 != 0, h[0]&0x0f
		if h[0]&0x70 != 0 {
			return nil, c.fail(1002, "reserved bits set")
		}
		if h[1]&0x80 == 0 {
			return nil, c.fail(1002, "client frames must be masked")
		}
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(c.r, b[:]); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(c.r, b[:]); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if op >= 8 && (n > 125 || !fin) {
			return nil, c.fail(1002, "bad control frame")
		}
		if n > uint64(c.MaxFrame) || uint64(len(msg))+n > uint64(c.MaxFrame) {
			return nil, c.fail(1009, "message too big")
		}
		var mask [4]byte
		if _, err := io.ReadFull(c.r, mask[:]); err != nil {
			return nil, err
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(c.r, p); err != nil {
			return nil, err
		}
		for i := range p {
			p[i] ^= mask[i&3]
		}
		switch op {
		case 0x8: // close
			c.writeFrame(0x8, p)
			c.c.Close()
			return nil, ErrClosed
		case 0x9: // ping
			if err := c.writeFrame(0xA, p); err != nil {
				return nil, err
			}
			continue
		case 0xA: // pong
			continue
		case 0x1:
			return nil, c.fail(1003, "binary frames only")
		case 0x2:
			if started {
				return nil, c.fail(1002, "new message inside a fragmented one")
			}
			started, msg = true, p
		case 0x0:
			if !started {
				return nil, c.fail(1002, "continuation without a start")
			}
			msg = append(msg, p...)
		default:
			return nil, c.fail(1002, "unknown opcode")
		}
		if fin {
			return msg, nil
		}
	}
}

// Write sends one binary message. Safe for concurrent use.
func (c *Conn) Write(p []byte) error { return c.writeFrame(0x2, p) }

func (c *Conn) writeFrame(op byte, p []byte) error {
	var h [10]byte
	h[0] = 0x80 | op
	n := len(p)
	hl := 2
	switch {
	case n < 126:
		h[1] = byte(n)
	case n < 65536:
		h[1] = 126
		binary.BigEndian.PutUint16(h[2:], uint16(n))
		hl = 4
	default:
		h[1] = 127
		binary.BigEndian.PutUint64(h[2:], uint64(n))
		hl = 10
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.c.Write(h[:hl]); err != nil {
		return err
	}
	_, err := c.c.Write(p)
	return err
}

func (c *Conn) fail(code uint16, reason string) error {
	c.Close(code, reason)
	return errors.New("ws: " + reason)
}

// Close sends a close frame with a code and closes the connection.
func (c *Conn) Close(code uint16, reason string) {
	p := make([]byte, 2, 2+len(reason))
	binary.BigEndian.PutUint16(p, code)
	c.writeFrame(0x8, append(p, reason...))
	c.c.Close()
}
