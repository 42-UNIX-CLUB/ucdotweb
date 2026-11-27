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

	reasonVoluntary = 0x02
	reasonNetwork   = 0x03
	reasonInvalid   = 0x41
	reasonUnreach   = 0x42
	reasonTimeout   = 0x43
	reasonRefused   = 0x44
	reasonBlocked   = 0x48
	reasonThrottled = 0x49
	buffer          = 128 // DATA packets a client may send per stream before waiting for CONTINUE
	// maxQueued is the most client bytes a stream may have waiting for the far end. Credit
	// counts packets and a packet may be 1 MiB, so without it one stream could make the relay
	// hold 128 MiB. The OS's client sends DATA packets of up to 64 KiB, so a full credit of
	// those (128 x 64 KiB = 8 MiB) must fit: an honest client never reaches the cap.
	maxQueued = buffer * 64 << 10
	// refusalLogsPerMin is how many refused CONNECTs of each outcome are logged per user a
	// minute; the rest are only answered. Per outcome, so a flood of one kind (a refused port)
	// cannot hide a limit trip that the safety watcher and the administrators read.
	refusalLogsPerMin = 10
	tokenPrefix       = "ucos-token."
	recheckInterval   = 5 * time.Second
	usageFlushPeriod  = 10 * time.Second
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
	starts  []time.Time // streams opened in the last minute, for streams_per_min
	// refusals logged in the current minute, so a client cannot fill the log with refusals
	refusedAt time.Time
	refused   map[string]int // outcome -> refusals in the minute from refusedAt
}

// idle reports whether the state can be dropped: no socket, nothing to write, and no
// destination or logged refusal counted in the last minute (else closing and reopening the
// socket would reset those limits). Called under rl.mu.
func (us *userState) idle(now time.Time) bool {
	if us.refs > 0 || us.pending > 0 {
		return false
	}
	if us.refused != nil && now.Sub(us.refusedAt) <= time.Minute {
		return false // keeps the count of logged refusals for its minute
	}
	if n := len(us.starts); n > 0 && now.Sub(us.starts[n-1]) <= time.Minute {
		return false // keeps the streams-a-minute count across a reconnect
	}
	for _, t := range us.dests {
		if now.Sub(t) <= time.Minute {
			return false
		}
	}
	return true
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
	used, err := rl.usedToday(claims.Sub, us)
	if err != nil {
		http.Error(w, "Quota unavailable.", http.StatusServiceUnavailable)
		return
	}
	if q.BytesPerDay > 0 && used >= q.BytesPerDay {
		if rl.logAllowed(us, "daily quota") {
			_ = rl.DB.LogConn(claims.Sub, "relay", "", 0, "daily quota")
		}
		http.Error(w, "Daily relay quota reached. It resets at 00:00 UTC.", http.StatusTooManyRequests)
		return
	}
	c, err := ws.Upgrade(w, r, "wisp")
	if err != nil {
		return
	}
	s := &session{rl: rl, c: c, sub: claims.Sub, sid: claims.Sid, us: us, streams: map[uint32]*stream{}}
	s.q.Store(&q)
	s.run()
}

func (rl *Relay) acquire(sub string) *userState {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.users == nil {
		rl.users = map[string]*userState{}
	}
	now := time.Now()
	for s, u := range rl.users { // drop states kept only for their recent destinations
		if s != sub && u.idle(now) {
			delete(rl.users, s)
		}
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
		if us.idle(time.Now()) {
			delete(rl.users, sub)
		}
	}
}

// logAllowed counts one refusal of a kind for the user and says whether it may still be
// logged this minute (refusalLogsPerMin per kind). Every refusal path that writes a row goes
// through it, so no kind of refusal can fill the log.
func (rl *Relay) logAllowed(us *userState, kind string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if us.refused == nil || now.Sub(us.refusedAt) > time.Minute {
		us.refusedAt, us.refused = now, map[string]int{}
	}
	us.refused[kind]++
	return us.refused[kind] <= refusalLogsPerMin
}

// recentStarts drops stream starts older than a minute and returns how many are left.
// Called under rl.mu.
func recentStarts(us *userState, now time.Time) int {
	i := 0
	for i < len(us.starts) && now.Sub(us.starts[i]) > time.Minute {
		i++
	}
	us.starts = us.starts[i:]
	return len(us.starts)
}

// FlushAll writes every user's pending usage to the database. The server calls it when it
// stops, so the bytes of open sockets since their last 10-second flush are not lost.
func (rl *Relay) FlushAll() {
	rl.mu.Lock()
	all := make(map[string]*userState, len(rl.users))
	for sub, us := range rl.users {
		all[sub] = us
	}
	rl.mu.Unlock()
	for sub, us := range all {
		rl.flush(sub, us)
	}
}

// usedToday returns today's bytes for the user, counting what is not flushed yet.
// A failed read is returned as an error, never as zero: the quota must fail closed.
func (rl *Relay) usedToday(sub string, us *userState) (int64, error) {
	day := store.Day(time.Now())
	rl.mu.Lock()
	stale := us.used < 0 || us.day != day
	rl.mu.Unlock()
	if stale {
		b, _, err := rl.DB.UsageToday(sub, "relay")
		if err != nil {
			return 0, err
		}
		rl.mu.Lock()
		if us.used < 0 || us.day != day {
			us.used, us.day = b, day
		}
		rl.mu.Unlock()
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return us.used, nil
}

// account adds bytes and reports whether the user is still within the daily quota.
func (rl *Relay) account(us *userState, n int64, limit int64) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if day := store.Day(time.Now()); us.day != day { // a transfer running across 00:00 UTC
		us.used, us.day = 0, day
	}
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
	q        atomic.Pointer[store.Quota] // the member tier's limits, re-read at every re-check
	us       *userState

	mu      sync.Mutex
	streams map[uint32]*stream
	closed  bool
}

type stream struct {
	id     uint32
	host   string
	in     chan []byte  // client to server, at most `buffer` packets
	queued atomic.Int64 // bytes in `in`, at most maxQueued
	bytes  atomic.Int64

	mu     sync.Mutex // guards conn and closed: a CLOSE may arrive while the dial runs
	conn   net.Conn
	closed bool

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
			if st.queued.Add(int64(len(body))) > maxQueued {
				s.closeStream(st, reasonInvalid, "flow control violated", true)
				continue
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
			if q, err := s.rl.DB.GetQuota("member"); err == nil {
				s.q.Store(&q) // an administrator's change reaches open sockets here
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
	s.refuseAs(id, host, reason, outcome, outcome)
}

// refuseAs answers a refused CONNECT and logs it, counting it under kind for the allowance
// of logged refusals: an outcome that carries a number (the port) still shares one allowance.
func (s *session) refuseAs(id uint32, host string, reason byte, outcome, kind string) {
	_ = s.send(pClose, id, []byte{reason})
	if s.rl.logAllowed(s.us, kind) {
		_ = s.rl.DB.LogConn(s.sub, "relay", host, 0, outcome)
	}
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
		s.refuseAs(id, host, reasonBlocked, fmt.Sprintf("port %d refused", port), "port refused")
		return
	}
	if s.rl.DB.CapReached("relay") {
		s.refuse(id, host, reasonThrottled, "platform cap")
		return
	}
	dest := fmt.Sprintf("%s:%d", host, port)
	rl := s.rl
	q := s.q.Load()
	if _, err := rl.usedToday(s.sub, s.us); err != nil { // a socket open across 00:00 UTC starts the new day here
		s.refuse(id, host, reasonThrottled, "quota unavailable")
		return
	}
	rl.mu.Lock()
	now := time.Now()
	for d, t := range s.us.dests {
		if now.Sub(t) > time.Minute {
			delete(s.us.dests, d)
		}
	}
	_, recent := s.us.dests[dest]
	switch {
	case q.Conns > 0 && s.us.streams >= q.Conns:
		rl.mu.Unlock()
		s.refuse(id, host, reasonThrottled, "too many connections")
		return
	case q.StreamsPerMin > 0 && recentStarts(s.us, now) >= q.StreamsPerMin:
		rl.mu.Unlock()
		s.refuse(id, host, reasonThrottled, "too many streams")
		return
	case !recent && q.DestsPerMin > 0 && len(s.us.dests) >= q.DestsPerMin:
		rl.mu.Unlock()
		s.refuse(id, host, reasonThrottled, "too many destinations")
		return
	case q.BytesPerDay > 0 && s.us.used >= q.BytesPerDay:
		rl.mu.Unlock()
		s.refuse(id, host, reasonThrottled, "daily quota")
		return
	}

	if !recent {
		s.us.dests[dest] = now
	}
	s.us.starts = append(s.us.starts, now) // every stream counts, the same destination and failed dials too
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
	st.mu.Lock()
	if st.closed { // closed while dialing: do not keep a connection nobody owns
		st.mu.Unlock()
		conn.Close()
		return
	}
	st.conn = conn
	st.mu.Unlock()
	if s.send(pContinue, st.id, u32(buffer)) != nil {
		s.closeStream(st, reasonNetwork, "socket gone", false)
		return
	}
	go s.upstreamWriter(ctx, st, conn)
	buf := make([]byte, 32<<10)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			st.bytes.Add(int64(n))
			ok := s.rl.account(s.us, int64(n), s.q.Load().BytesPerDay)
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
func (s *session) upstreamWriter(ctx context.Context, st *stream, conn net.Conn) {
	written := 0
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-st.in:
			st.queued.Add(-int64(len(p)))
			// counted before the write: the far end may answer at once, and a close that
			// follows the answer must log these bytes too
			st.bytes.Add(int64(len(p)))
			ok := s.rl.account(s.us, int64(len(p)), s.q.Load().BytesPerDay)
			if _, err := conn.Write(p); err != nil {
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
		st.mu.Lock()
		st.closed = true
		conn := st.conn
		st.mu.Unlock()
		if conn != nil {
			conn.Close()
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
		// a stream that never connected (blocked address, unreachable, timeout) is a refusal:
		// it shares the per-kind allowance, so failed dials cannot fill the log
		if conn != nil || s.rl.logAllowed(s.us, outcome) {
			_ = s.rl.DB.LogConn(s.sub, "relay", st.host, st.bytes.Load(), outcome)
		}
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
