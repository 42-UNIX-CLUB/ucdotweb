package ws

import (
	"errors"
	"net"
	"testing"
	"time"
)

// brokenConn accepts the first `good` bytes written and then fails every write, like a peer
// that stopped reading until the write deadline passed.
type brokenConn struct {
	net.Conn // nil: only the methods below are used
	good     int
	wrote    int
	after    int // bytes offered after the first failure
	failed   bool
	closed   bool
}

func (b *brokenConn) Write(p []byte) (int, error) {
	if b.closed {
		return 0, net.ErrClosed
	}
	if b.failed {
		b.after += len(p)
		return len(p), nil // a later write goes through: the client now sees bytes with no frame around them
	}
	if b.wrote+len(p) > b.good {
		n := b.good - b.wrote
		if n < 0 {
			n = 0
		}
		b.wrote += n
		b.failed = true
		return n, errors.New("i/o timeout")
	}
	b.wrote += len(p)
	return len(p), nil
}
func (b *brokenConn) Close() error                     { b.closed = true; return nil }
func (b *brokenConn) SetWriteDeadline(time.Time) error { return nil }
func (b *brokenConn) SetReadDeadline(time.Time) error  { return nil }
func (b *brokenConn) SetDeadline(time.Time) error      { return nil }

// Finding 11: a write that fails part way (here: the frame header went out, the payload did
// not) leaves the connection open. The next message is then written after half a frame, and
// the client reads its bytes as the missing payload.
func TestOptFailedWriteClosesTheConnection(t *testing.T) {
	bc := &brokenConn{good: 4} // the 4-byte header of a 1,000-byte frame fits, the payload does not
	c := &Conn{c: bc, MaxFrame: 1 << 20}
	if err := c.Write(make([]byte, 1000)); err == nil {
		t.Fatal("the write should have failed")
	}
	if !bc.closed {
		t.Errorf("after a failed write the connection is still open")
	}
	err := c.Write([]byte("next message"))
	if err == nil || bc.after > 0 {
		t.Errorf("a second message was written after the failed one (%d bytes sent, error %v): the stream is out of step", bc.after, err)
	}
}
