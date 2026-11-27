package safety

import (
	"context"
	"testing"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

// Finding SW1: the limits check reads every kind of connection log line, so three users who
// hit the PROXY's rate limit suspend the RELAY (the default switch).
func TestOptProxyRateLimitsSuspendTheRelay(t *testing.T) {
	db, err := store.Open(t.TempDir()+"/s.db", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w, err := New(db, DefaultConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"u1", "u2", "u3"} {
		if err := db.LogConn(u, "proxy", "deb.debian.org", 0, "rate limited"); err != nil {
			t.Fatal(err)
		}
	}
	st := w.Check(context.Background())
	if st.Suspended && st.Switch == "relay_off" {
		t.Errorf("three proxy users at the proxy's rate limit turned on %s: %v", st.Switch, st.LastTrip.Reasons)
	}
}
