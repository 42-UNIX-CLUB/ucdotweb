package proxy

import (
	"strings"
	"testing"
)

// Finding P3: a request that is refused as "not allowed" is logged before the rate limit is
// looked at, with the host exactly as the client wrote it. So one signed-in user can write
// any number of rows, each as long as a URL may be, and is never slowed down.
func TestOptRefusedRequestsAreLoggedWithoutLimit(t *testing.T) {
	r := newRig(t, true)
	r.db.Exec(`UPDATE quotas SET reqs_per_min = 5 WHERE tier = 'user'`)
	const n = 200
	codes := map[int]int{}
	for i := 0; i < n; i++ {
		resp := r.get(t, "/proxy/not-on-the-list.example/x", true)
		codes[resp.StatusCode]++
		resp.Body.Close()
	}
	var rows int
	r.db.QueryRow(`SELECT count(*) FROM conn_log WHERE outcome = 'not allowed'`, &rows)
	t.Logf("%d requests to a host off the list, rate limit 5 a minute: answers %v, %d log rows", n, codes, rows)
	if codes[429] == 0 {
		t.Errorf("none of %d refused requests in one burst was rate limited (limit: 5 a minute)", n)
	}
	if rows > 10 {
		t.Errorf("%d rows written to conn_log by one user in one burst", rows)
	}

	long := strings.Repeat("a", 200000) + ".example"
	resp := r.get(t, "/proxy/"+long+"/x", true)
	resp.Body.Close()
	var size int
	r.db.QueryRow(`SELECT max(length(host)) FROM conn_log`, &size)
	t.Logf("a host of %d characters: status %d, longest host stored %d characters", len(long), resp.StatusCode, size)
	if size > 253 {
		t.Errorf("a host of %d characters was stored in conn_log (a DNS name is at most 253)", size)
	}
}

// Finding P3, second half: once over the rate limit, every further request writes a row too.
func TestOptRateLimitedRequestsEachWriteARow(t *testing.T) {
	r := newRig(t, true)
	r.db.Exec(`UPDATE quotas SET reqs_per_min = 5 WHERE tier = 'user'`)
	for i := 0; i < 205; i++ {
		resp := r.get(t, "/proxy/deb.debian.org/debian/dists/stable/InRelease", true)
		resp.Body.Close()
	}
	var rows int
	r.db.QueryRow(`SELECT count(*) FROM conn_log WHERE outcome = 'rate limited'`, &rows)
	t.Logf("205 requests at a limit of 5 a minute: %d rows say rate limited", rows)
	if rows > 10 {
		t.Errorf("%d rate limited rows from one user in one minute", rows)
	}
}
