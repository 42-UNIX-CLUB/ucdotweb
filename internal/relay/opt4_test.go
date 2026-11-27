package relay

import (
	"testing"
	"time"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/netguard"
)

// The same for a destination the guard refuses: every attempt ends in closeStream with
// "blocked address" and writes a row, outside the refusal allowance.
func TestOptBlockedAddressAttemptsAreBounded(t *testing.T) {
	r := newRig(t)
	r.rl.Guard = &netguard.Guard{} // loopback is blocked, as in production
	c := open(t, r)
	const rounds = 500
	for i := uint32(1); i <= rounds; i++ {
		c.send(pConnect, i, connectBody(r.port, "127.0.0.1"))
		expectClose(t, c, i, reasonBlocked)
	}
	time.Sleep(300 * time.Millisecond)
	var rows int
	r.db.QueryRow(`SELECT count(*) FROM conn_log WHERE outcome = 'blocked address'`, &rows)
	t.Logf("%d CONNECTs to a blocked address: %d log rows", rounds, rows)
	if rows > 2*refusalLogsPerMin {
		t.Errorf("%d rows for attempts on a blocked address from one user in one burst", rows)
	}
}

// At the upgrade: a member at the daily quota is refused before the WebSocket opens, and each
// refusal writes a "daily quota" row with no allowance at all.
func TestOptUpgradeRefusalsAtQuotaAreBounded(t *testing.T) {
	r := newRig(t)
	r.db.Exec(`UPDATE quotas SET bytes_per_day = 10 WHERE tier = 'member'`)
	r.db.AddUsage("u1", "relay", 20, 1)
	const tries = 100
	for i := 0; i < tries; i++ {
		if _, code := dial(t, r, origin, "wisp, ucos-token."+r.token(t)); code != 429 {
			t.Fatalf("upgrade %d: %d, want 429", i, code)
		}
	}
	var rows int
	r.db.QueryRow(`SELECT count(*) FROM conn_log WHERE outcome = 'daily quota'`, &rows)
	t.Logf("%d upgrade attempts at the daily quota: %d log rows", tries, rows)
	if rows > 2*refusalLogsPerMin {
		t.Errorf("%d rows for upgrade attempts at the quota", rows)
	}
}
