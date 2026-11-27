package relay

import (
	"testing"
	"time"
)

// Review of the second fix for the refusal log (at most 10 rows per outcome, per user, a
// minute). The outcome of a refused port carries the port number ("port 22 refused"), so
// every port is its own outcome with its own allowance: a client that walks the ports
// writes a row for each, as before the fix.
func TestOptRefusedPortsShareOneAllowance(t *testing.T) {
	r := newRig(t)
	c := open(t, r)
	const ports = 300
	for i := uint32(1); i <= ports; i++ {
		c.send(pConnect, i, connectBody(1000+int(i), "127.0.0.1")) // 300 different ports, none allowed
		expectClose(t, c, i, reasonBlocked)
	}
	time.Sleep(300 * time.Millisecond)
	var rows int
	r.db.QueryRow(`SELECT count(*) FROM conn_log WHERE outcome LIKE 'port % refused'`, &rows)
	t.Logf("%d CONNECTs to %d different refused ports: %d log rows", ports, ports, rows)
	if rows > 2*refusalLogsPerMin {
		t.Errorf("%d rows for refused ports from one user in one burst (the allowance is %d per outcome a minute)", rows, refusalLogsPerMin)
	}
}
