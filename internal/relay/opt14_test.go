package relay

import (
	"testing"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

// Finding 14a: the day of the user's counter is looked at only when a socket is opened. A
// socket that stays open across 00:00 UTC keeps yesterday's total, so a user who reached the
// limit yesterday is still refused today ("It resets at 00:00 UTC" is not true for them).
// The test stands in for the night: it puts the open socket's counter at the limit with
// yesterday's date, while the database has no usage for today.
func TestOptDailyCounterFollowsTheDay(t *testing.T) {
	r := newRig(t)
	r.db.Exec(`UPDATE quotas SET bytes_per_day = 1000 WHERE tier = 'member'`)
	c := open(t, r)
	r.rl.mu.Lock()
	us := r.rl.users["u1"]
	us.used, us.day = 1000, store.Day(time.Now().AddDate(0, 0, -1)) // at the limit, yesterday
	r.rl.mu.Unlock()
	c.send(pConnect, 1, connectBody(r.port, "127.0.0.1"))
	typ, id, body, ok := c.read(t)
	if !ok {
		t.Fatal("socket closed")
	}
	if typ == pClose && id == 1 {
		t.Errorf("a new day, no usage today, and the stream is refused with reason %#x (0x49 is throttled)", body[0])
	}
}

// Finding 14b: the quota is read once, when the socket is opened. A change by an
// administrator does not reach a socket that is already open, however long it stays open.
func TestOptQuotaChangeReachesOpenSockets(t *testing.T) {
	r := newRig(t) // the rig re-checks every 100 ms
	c := open(t, r)
	if err := r.db.SetQuota("admin", "member", store.Quota{BytesPerDay: 2500000000, Conns: 1, DestsPerMin: 15, ReqsPerMin: 120}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond) // five re-checks
	c.send(pConnect, 1, connectBody(r.port, "127.0.0.1"))
	if typ, id, _, _ := c.read(t); typ != pContinue || id != 1 {
		t.Fatalf("first stream: packet %d on %d", typ, id)
	}
	c.send(pConnect, 2, connectBody(r.port, "127.0.0.1"))
	typ, id, body, ok := c.read(t)
	if !ok {
		t.Fatal("socket closed")
	}
	if typ == pClose && id == 2 && body[0] == reasonThrottled {
		return
	}
	t.Errorf("the limit was lowered to 1 connection half a second ago, and a second stream got packet %d on stream %d (3 is CONTINUE: connected)", typ, id)
}
