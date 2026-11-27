// Package relay is the members' TCP relay: Wisp v1 framing over one WebSocket (decided:
// Wisp-compatible for now). A browser opens /relay with a 5-minute relay token; each Wisp
// stream becomes one TCP connection to a public address on an allowed port. Quotas per user
// (decided: 2.5 GB a day, 8 simultaneous connections, 15 new destinations a minute, ports 80
// and 443), the panic switches, bans and sign-out are enforced on live connections too.
//
// The token travels in the WebSocket subprotocol list ("wisp", "ucos-token.<token>") because
// a browser cannot set headers on a WebSocket and a URL query would end up in access logs.
package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/netguard"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
	"github.com/42-UNIX-CLUB/ucdotweb/internal/ws"
)

// Wisp v1 packet types and close reasons.
const (
	pConnect  = 1
	pData     = 2
	pContinue = 3
	pClose    = 4

	reasonVoluntary  = 0x02
	reasonNetwork    = 0x03
	reasonInvalid    = 0x41
	reasonUnreach    = 0x42
	reasonTimeout    = 0x43
	reasonRefused    = 0x44
	reasonBlocked    = 0x48
	reasonThrottled  = 0x49
	buffer           = 128 // DATA packets a client may send per stream before waiting for CONTINUE
	tokenPrefix      = "ucos-token."
	recheckInterval  = 5 * time.Second
	usageFlushPeriod = 10 * time.Second
)

// Check answers whether a subject with a session may still use the relay: the session
// exists, the user is a member, not banned. The web package provides it.
type Check func(subject, sid string) error

// Relay is the handler.
type Relay struct {
	Verifier *Verifier
	DB       *store.DB
	Origin   string // our page's origin; other origins are refused
	Check    Check
	Guard    *netguard.Guard
	Ports    []int // allowed destination ports
	Log      *log.Logger
	Recheck  time.Duration // how often a live socket re-checks the user and switches; 0: 5 s

	mu    sync.Mutex
	users map[string]*userState // live state per subject, shared by all of a user's sockets
}

type userState struct {
	streams int
	dests   map[string]time.Time // destination -> last time it was first connected
	used    int64                // bytes today, loaded from the database at first use
	pending int64                // bytes not yet written to the database
	day     string
	refs    int
}

func (rl *Relay) logf(f string, a ...any) {
	if rl.Log != nil {
		rl.Log.Printf("relay: "+f, a...)
	}
}

func (rl *Relay) off() bool { return rl.DB.Flag("relay_off") || rl.DB.Flag("all_off") }

// ServeHTTP upgrades /relay and runs the session.
func (rl *Relay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != rl.Origin {
		http.Error(w, "Wrong origin.", http.StatusForbidden)
		return
	}
	var tok string
	wisp := false
	for _, p := range ws.Protocols(r) {
		if p == "wisp" {
			wisp = true
		} else if strings.HasPrefix(p, tokenPrefix) {
			tok = strings.TrimPrefix(p, tokenPrefix)
		}
	}
	if !wisp || tok == "" {
		http.Error(w, "Offer the wisp subprotocol and a relay token.", http.StatusBadRequest)
		return
	}
	claims, err := rl.Verifier.Verify(tok, time.Now())
	if err != nil {
		http.Error(w, "Relay token refused.", http.StatusUnauthorized)
		return
	}
	if rl.off() {
		http.Error(w, "The relay is switched off by the administrators.", http.StatusServiceUnavailable)
		return
	}
	if rl.DB.CapReached("relay") {
		http.Error(w, "The platform's daily relay limit is reached. It resets at 00:00 UTC.", http.StatusServiceUnavailable)
		return
	}
	if err := rl.Check(claims.Sub, claims.Sid); err != nil {
		http.Error(w, "Not allowed to use the relay: "+err.Error(), http.StatusForbidden)
		return
	}
	q, err := rl.DB.GetQuota("member")
	if err != nil {
		http.Error(w, "Quota unavailable.", http.StatusInternalServerError)
		return
	}
	us := rl.acquire(claims.Sub)
	defer rl.release(claims.Sub)
	if q.BytesPerDay > 0 && rl.usedToday(claims.Sub, us) >= q.BytesPerDay {
		_ = rl.DB.LogConn(claims.Sub, "relay", "", 0, "daily quota")
		http.Error(w, "Daily relay quota reached. It resets at 00:00 UTC.", http.StatusTooManyRequests)
		return
	}
	c, err := ws.Upgrade(w, r, "wisp")
	if err != nil {
		return
	}
	s := &session{rl: rl, c: c, sub: claims.Sub, sid: claims.Sid, q: q, us: us, streams: map[uint32]*stream{}}
	s.run()
}

func (rl *Relay) acquire(sub string) *userState {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.users == nil {
		rl.users = map[string]*userState{}
	}
	us := rl.users[sub]
	if us == nil {
		us = &userState{dests: map[string]time.Time{}, used: -1}
		rl.users[sub] = us
	}
	us.refs++
	return us
}

func (rl *Relay) release(sub string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if us := rl.users[sub]; us != nil {
		us.refs--
		if us.refs == 0 && us.pending == 0 {
			delete(rl.users, sub)
		}
	}
}

// usedToday returns today's bytes for the user, counting what is not flushed yet.
func (rl *Relay) usedToday(sub string, us *userState) int64 {
	day := store.Day(time.Now())
	rl.mu.Lock()
	stale := us.used < 0 || us.day != day
	rl.mu.Unlock()
	if stale {
		b, _, _ := rl.DB.UsageToday(sub, "relay")
		rl.mu.Lock()
		if us.used < 0 || us.day != day {
			us.used, us.day = b, day
		}
		rl.mu.Unlock()
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return us.used
}

// account adds bytes and reports whether the user is still within the daily quota.
func (rl *Relay) account(us *userState, n int64, limit int64) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	us.used += n
	us.pending += n
	return limit <= 0 || us.used <= limit
}

func (rl *Relay) flush(sub string, us *userState) {
	rl.mu.Lock()
	n := us.pending
	us.pending = 0
	rl.mu.Unlock()
	if n > 0 {
		_ = rl.DB.AddUsage(sub, "relay", n, 0)
	}
}

// ---- one WebSocket ----

type session struct {
	rl       *Relay
	c        *ws.Conn
	sub, sid string
	q        store.Quota
	us       *userState

	mu      sync.Mutex
	streams map[uint32]*stream
	closed  bool
}

type stream struct {
	id     uint32
	host   string
	conn   net.Conn
	in     chan []byte // client to server, at most `buffer` packets
	bytes  atomic.Int64
	once   sync.Once
	cancel context.CancelFunc
}

func packet(t byte, id uint32, payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	b[0] = t
	binary.LittleEndian.PutUint32(b[1:], id)
	copy(b[5:], payload)
	return b
}

func u32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

func (s *session) send(t byte, id uint32, payload []byte) error {
	return s.c.Write(packet(t, id, payload))
}

func (s *session) run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer s.shutdown()
	go s.watch(ctx)
	if s.send(pContinue, 0, u32(buffer)) != nil {
		return
	}
	for {
		msg, err := s.c.Read()
		if err != nil {
			return
		}
		if len(msg) < 5 {
			s.c.Close(1002, "short packet")
			return
		}
		t, id, body := msg[0], binary.LittleEndian.Uint32(msg[1:5]), msg[5:]
		switch t {
		case pConnect:
			s.connect(ctx, id, body)
		case pData:
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			if st == nil {
				continue // data for a stream already closed: ignore
			}
			select {
			case st.in <- append([]byte(nil), body...):
			default: // the client ignored flow control
				s.closeStream(st, reasonInvalid, "flow control violated", true)
			}
		case pClose:
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			if st != nil {
				s.closeStream(st, reasonVoluntary, "closed by client", false)
			}
		default:
			s.c.Close(1002, "unknown packet type")
			return
		}
	}
}

// watch re-checks the user and the switches, and flushes usage, while the socket is open.
func (s *session) watch(ctx context.Context) {
	every := s.rl.Recheck
	if every == 0 {
		every = recheckInterval
	}
	check := time.NewTicker(every)
	flush := time.NewTicker(usageFlushPeriod)
	defer check.Stop()
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-flush.C:
			s.rl.flush(s.sub, s.us)
		case <-check.C:
			if s.rl.off() {
				s.c.Close(1008, "relay switched off")
				return
			}
			if err := s.rl.Check(s.sub, s.sid); err != nil {
				s.c.Close(1008, "access ended")
				return
			}
		}
	}
}

func (s *session) portAllowed(p int) bool {
	for _, a := range s.rl.Ports {
		if a == p {
			return true
		}
	}
	return false
}

func (s *session) refuse(id uint32, host string, reason byte, outcome string) {
	_ = s.send(pClose, id, []byte{reason})
	_ = s.rl.DB.LogConn(s.sub, "relay", host, 0, outcome)
}

func (s *session) connect(ctx context.Context, id uint32, body []byte) {
	if len(body) < 3 || body[0] != 1 { // TCP only
		_ = s.send(pClose, id, []byte{reasonInvalid})
		return
	}
	port := int(binary.LittleEndian.Uint16(body[1:3]))
	host := strings.ToLower(string(body[3:]))
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\@\x00") {
		_ = s.send(pClose, id, []byte{reasonInvalid})
		return
	}
	s.mu.Lock()
	_, dup := s.streams[id]
	s.mu.Unlock()
	if dup || id == 0 {
		_ = s.send(pClose, id, []byte{reasonInvalid})
		return
	}
	if s.rl.off() {
		s.refuse(id, host, reasonBlocked, "relay off")
		return
	}
	if !s.portAllowed(port) {
		s.refuse(id, host, reasonBlocked, fmt.Sprintf("port %d refused", port))
		return
	}
	if s.rl.DB.CapReached("relay") {
		s.refuse(id, host, reasonThrottled, "platform cap")
		return
	}
	dest := fmt.Sprintf("%s:%d", host, port)
	rl := s.rl
	rl.mu.Lock()
	now := time.Now()
	for d, t := range s.us.dests {
		if now.Sub(t) > time.Minute {
			delete(s.us.dests, d)
		}
	}
	_, recent := s.us.dests[dest]
	switch {
	case s.q.Conns > 0 && s.us.streams >= s.q.Conns:
		rl.mu.Unlock()
		s.refuse(id, host, reasonThrottled, "too many connections")
		return
	case !recent && s.q.DestsPerMin > 0 && len(s.us.dests) >= s.q.DestsPerMin:
		rl.mu.Unlock()
		s.refuse(id, host, reasonThrottled, "too many destinations")
		return
	case s.q.BytesPerDay > 0 && s.us.used >= s.q.BytesPerDay:
		rl.mu.Unlock()
		s.refuse(id, host, reasonThrottled, "daily quota")
		return
	}

	if !recent {
		s.us.dests[dest] = now
	}
	s.us.streams++
	rl.mu.Unlock()

	sctx, cancel := context.WithCancel(ctx)
	st := &stream{id: id, host: host, in: make(chan []byte, buffer), cancel: cancel}
	s.mu.Lock()
	s.streams[id] = st
	s.mu.Unlock()
	go s.dial(sctx, st, dest)
}

func (s *session) dial(ctx context.Context, st *stream, dest string) {
	g := s.rl.Guard
	if g == nil {
		g = &netguard.Guard{}
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, err := g.DialContext(dctx, "tcp", dest)
	cancel()
	if err != nil {
		reason, outcome := byte(reasonUnreach), "unreachable"
		var ne net.Error
		switch {
		case errors.Is(err, netguard.ErrBlocked):
			reason, outcome = reasonBlocked, "blocked address"
		case errors.As(err, &ne) && ne.Timeout():
			reason, outcome = reasonTimeout, "timeout"
		case strings.Contains(err.Error(), "refused"):
			reason, outcome = reasonRefused, "refused"
		}
		s.closeStream(st, reason, outcome, true)
		return
	}
	st.conn = conn
	if s.send(pContinue, st.id, u32(buffer)) != nil {
		s.closeStream(st, reasonNetwork, "socket gone", false)
		return
	}
	go s.upstreamWriter(ctx, st)
	buf := make([]byte, 32<<10)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			st.bytes.Add(int64(n))
			ok := s.rl.account(s.us, int64(n), s.q.BytesPerDay)
			if s.send(pData, st.id, buf[:n]) != nil {
				s.closeStream(st, reasonNetwork, "socket gone", false)
				return
			}
			if !ok {
				s.closeStream(st, reasonThrottled, "cut at daily quota", true)
				return
			}
		}
		if err != nil {
			s.closeStream(st, reasonVoluntary, "closed by server", true)
			return
		}
	}
}

// upstreamWriter writes client data to the TCP connection and returns flow-control credit.
func (s *session) upstreamWriter(ctx context.Context, st *stream) {
	written := 0
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-st.in:
			// counted before the write: the far end may answer at once, and a close that
			// follows the answer must log these bytes too
			st.bytes.Add(int64(len(p)))
			ok := s.rl.account(s.us, int64(len(p)), s.q.BytesPerDay)
			if _, err := st.conn.Write(p); err != nil {
				s.closeStream(st, reasonNetwork, "write failed", true)
				return
			}
			if !ok {
				s.closeStream(st, reasonThrottled, "cut at daily quota", true)
				return
			}
			written++
			if written%16 == 0 || len(st.in) == 0 {
				_ = s.send(pContinue, st.id, u32(uint32(buffer-len(st.in))))
			}
		}
	}
}

// closeStream ends a stream once: tells the client (if notify), closes the socket, frees
// the user's connection slot and logs host, bytes and outcome.
func (s *session) closeStream(st *stream, reason byte, outcome string, notify bool) {
	st.once.Do(func() {
		st.cancel()
		if st.conn != nil {
			st.conn.Close()
		}
		s.mu.Lock()
		delete(s.streams, st.id)
		s.mu.Unlock()
		s.rl.mu.Lock()
		s.us.streams--
		s.rl.mu.Unlock()
		if notify {
			_ = s.send(pClose, st.id, []byte{reason})
		}
		_ = s.rl.DB.LogConn(s.sub, "relay", st.host, st.bytes.Load(), outcome)
		_ = s.rl.DB.AddUsage(s.sub, "relay", 0, 1)
	})
}

func (s *session) shutdown() {
	s.mu.Lock()
	all := make([]*stream, 0, len(s.streams))
	for _, st := range s.streams {
		all = append(all, st)
	}
	s.mu.Unlock()
	for _, st := range all {
		s.closeStream(st, reasonNetwork, "socket closed", false)
	}
	s.rl.flush(s.sub, s.us)
}
