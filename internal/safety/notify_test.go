package safety

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWebhookFormats(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]string
	var ctypes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		got = append(got, m)
		ctypes = append(ctypes, r.Header.Get("Content-Type"))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	for _, field := range []string{"content", "text"} {
		h := &Webhook{URL: srv.URL + "/hook", Field: field}
		if err := h.Notify(t.Context(), "Subject line", "Body text."); err != nil {
			t.Fatalf("%s: %v", field, err)
		}
	}
	if len(got) != 2 || got[0]["content"] != "Subject line\nBody text." || got[1]["text"] != "Subject line\nBody text." ||
		len(got[0]) != 1 || len(got[1]) != 1 || ctypes[0] != "application/json" {
		t.Fatalf("bodies %v, types %v", got, ctypes)
	}
	long := &Webhook{URL: srv.URL, Field: "content"}
	if err := long.Notify(t.Context(), "s", strings.Repeat("x", 5000)); err != nil || len(got[2]["content"]) > 2000 {
		t.Fatalf("long message: %v, %d characters", err, len(got[2]["content"]))
	}
}

func TestWebhookErrorsHideTheURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	h := &Webhook{URL: srv.URL + "/hooks/SECRET-TOKEN", Field: "text"}
	if err := h.Notify(t.Context(), "s", "t"); err == nil || !strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error on 500: %v", err)
	}
	srv.Close()
	if err := h.Notify(t.Context(), "s", "t"); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error on a closed server: %v", err)
	}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := t.TempDir() + "/f"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNotifierFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	n, err := NotifierFromEnv(env(nil))
	if err != nil || n != nil {
		t.Fatalf("nothing set: %v %v", n, err)
	}
	n, err = NotifierFromEnv(env(map[string]string{"UCDOTWEB_WEBHOOK_URL_FILE": writeFile(t, "https://discord.com/api/webhooks/1/x\n")}))
	if err != nil || n.(Multi)[0].(*Webhook).Field != "content" {
		t.Fatalf("discord: %v %v", n, err)
	}
	n, err = NotifierFromEnv(env(map[string]string{"UCDOTWEB_WEBHOOK_URL_FILE": writeFile(t, "https://hooks.slack.com/services/x")}))
	if err != nil || n.(Multi)[0].(*Webhook).Field != "text" {
		t.Fatalf("slack: %v %v", n, err)
	}
	n, err = NotifierFromEnv(env(map[string]string{"UCDOTWEB_WEBHOOK_URL_FILE": writeFile(t, "https://chat.example/hook"),
		"UCDOTWEB_WEBHOOK_FORMAT": "content"}))
	if err != nil || n.(Multi)[0].(*Webhook).Field != "content" {
		t.Fatalf("forced format: %v %v", n, err)
	}
	auth := writeFile(t, "mailer\ns3cret\n")
	n, err = NotifierFromEnv(env(map[string]string{"UCDOTWEB_SMTP_HOST": "mail.example", "UCDOTWEB_SMTP_FROM": "ucdotweb@example.org",
		"UCDOTWEB_SMTP_TO": "a@example.org, b@example.org", "UCDOTWEB_SMTP_AUTH_FILE": auth,
		"UCDOTWEB_WEBHOOK_URL_FILE": writeFile(t, "https://chat.example/hook")}))
	if err != nil || len(n.(Multi)) != 2 || n.Name() != "webhook,email" {
		t.Fatalf("both: %v %v", n, err)
	}
	m := n.(Multi)[1].(*Mail)
	if m.Port != 587 || len(m.To) != 2 || m.User != "mailer" || m.Password != "s3cret" {
		t.Fatalf("mail config: %+v", m)
	}
	for i, bad := range []map[string]string{
		{"UCDOTWEB_WEBHOOK_URL_FILE": writeFile(t, "http://chat.example/hook")},
		{"UCDOTWEB_WEBHOOK_URL_FILE": "/nonexistent/file"},
		{"UCDOTWEB_WEBHOOK_URL_FILE": writeFile(t, "https://chat.example/hook"), "UCDOTWEB_WEBHOOK_FORMAT": "matrix"},
		{"UCDOTWEB_SMTP_HOST": "mail.example", "UCDOTWEB_SMTP_TO": "a@example.org"},
		{"UCDOTWEB_SMTP_HOST": "mail.example", "UCDOTWEB_SMTP_FROM": "x@example.org"},
		{"UCDOTWEB_SMTP_HOST": "mail.example", "UCDOTWEB_SMTP_FROM": "x@example.org", "UCDOTWEB_SMTP_TO": "a@example.org", "UCDOTWEB_SMTP_PORT": "0"},
		{"UCDOTWEB_SMTP_HOST": "mail.example", "UCDOTWEB_SMTP_FROM": "x@example.org", "UCDOTWEB_SMTP_TO": "a@example.org", "UCDOTWEB_SMTP_AUTH_FILE": writeFile(t, "onlyuser")},
	} {
		if _, err := NotifierFromEnv(env(bad)); err == nil {
			t.Fatalf("case %d accepted: %v", i, bad)
		}
	}
}

// ---- a fake SMTP server on 127.0.0.1 ----

type fakeSMTP struct {
	ln       net.Listener
	tlsCfg   *tls.Config
	startTLS bool

	mu       sync.Mutex
	cmds     []string // commands as received, with whether TLS was on
	auth     string   // decoded AUTH PLAIN
	rcpts    []string
	data     string
	authInTL bool
	done     chan struct{}
}

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake smtp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func newFakeSMTP(t *testing.T, startTLS bool) (*fakeSMTP, *x509.CertPool) {
	t.Helper()
	cert, pool := testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}}, startTLS: startTLS, done: make(chan struct{})}
	t.Cleanup(func() { ln.Close() })
	go f.serve()
	return f, pool
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve() {
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer close(f.done)
	defer func() { conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	tp := textproto.NewConn(conn)
	inTLS := false
	_ = tp.PrintfLine("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		f.mu.Lock()
		f.cmds = append(f.cmds, cmd+" tls="+strconv.FormatBool(inTLS))
		f.mu.Unlock()
		switch cmd {
		case "EHLO":
			switch {
			case inTLS:
				_ = tp.PrintfLine("250-fake\r\n250-AUTH PLAIN\r\n250 8BITMIME")
			case f.startTLS:
				_ = tp.PrintfLine("250-fake\r\n250-STARTTLS\r\n250 8BITMIME")
			default:
				_ = tp.PrintfLine("250-fake\r\n250-AUTH PLAIN\r\n250 8BITMIME")
			}
		case "STARTTLS":
			_ = tp.PrintfLine("220 go ahead")
			tc := tls.Server(conn, f.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn = tc
			tp = textproto.NewConn(tc)
			inTLS = true
		case "AUTH":
			parts := strings.Fields(line)
			if len(parts) == 3 {
				b, _ := base64.StdEncoding.DecodeString(parts[2])
				f.mu.Lock()
				f.auth, f.authInTL = string(b), inTLS
				f.mu.Unlock()
			}
			_ = tp.PrintfLine("235 ok")
		case "MAIL":
			_ = tp.PrintfLine("250 ok")
		case "RCPT":
			f.mu.Lock()
			f.rcpts = append(f.rcpts, line)
			f.mu.Unlock()
			_ = tp.PrintfLine("250 ok")
		case "DATA":
			_ = tp.PrintfLine("354 go")
			b, err := io.ReadAll(tp.DotReader())
			if err != nil {
				return
			}
			f.mu.Lock()
			f.data = string(b)
			f.mu.Unlock()
			_ = tp.PrintfLine("250 queued")
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("502 no")
		}
	}
}

func TestMailWithStartTLS(t *testing.T) {
	f, pool := newFakeSMTP(t, true)
	m := &Mail{Host: "127.0.0.1", Port: f.port(), From: "ucdotweb@example.org", To: []string{"a@example.org", "b@example.org"},
		User: "mailer", Password: "s3cret", RootCAs: pool}
	if err := m.Notify(t.Context(), "UC.OS safety: relay suspended", "Line one.\nLine two."); err != nil {
		t.Fatal(err)
	}
	<-f.done
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auth != "\x00mailer\x00s3cret" || !f.authInTL {
		t.Fatalf("auth %q in TLS %v", f.auth, f.authInTL)
	}
	if len(f.rcpts) != 2 || !strings.Contains(f.rcpts[1], "b@example.org") {
		t.Fatalf("recipients %v", f.rcpts)
	}
	r := textproto.NewReader(bufio.NewReader(strings.NewReader(f.data)))
	h, err := r.ReadMIMEHeader()
	if err != nil || h.Get("Subject") != "UC.OS safety: relay suspended" || h.Get("To") != "a@example.org, b@example.org" ||
		!strings.HasPrefix(h.Get("Content-Type"), "text/plain") {
		t.Fatalf("headers %v %v", h, err)
	}
	if !strings.Contains(f.data, "Line one.\nLine two.") { // the dot reader turns CRLF into LF
		t.Fatalf("body %q", f.data)
	}
	for _, c := range f.cmds {
		if (strings.HasPrefix(c, "AUTH") || strings.HasPrefix(c, "MAIL") || strings.HasPrefix(c, "DATA")) && !strings.HasSuffix(c, "tls=true") {
			t.Fatalf("%s before TLS: %v", c, f.cmds)
		}
	}
}

func TestMailRefusesWithoutStartTLS(t *testing.T) {
	f, pool := newFakeSMTP(t, false)
	m := &Mail{Host: "127.0.0.1", Port: f.port(), From: "x@example.org", To: []string{"a@example.org"},
		User: "mailer", Password: "s3cret", RootCAs: pool}
	if err := m.Notify(t.Context(), "s", "t"); !errors.Is(err, ErrNoStartTLS) {
		t.Fatalf("error %v, want ErrNoStartTLS", err)
	}
	<-f.done
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auth != "" || f.data != "" || len(f.rcpts) != 0 {
		t.Fatalf("something was sent without TLS: %v", f.cmds)
	}
}

func TestMailRefusesUntrustedCert(t *testing.T) {
	f, _ := newFakeSMTP(t, true)
	m := &Mail{Host: "127.0.0.1", Port: f.port(), From: "x@example.org", To: []string{"a@example.org"},
		User: "mailer", Password: "s3cret", RootCAs: x509.NewCertPool()}
	if err := m.Notify(t.Context(), "s", "t"); err == nil || !strings.Contains(err.Error(), "starttls") {
		t.Fatalf("error %v, want a TLS failure", err)
	}
	<-f.done
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auth != "" {
		t.Fatal("credentials sent over an unverified connection")
	}
}

func TestMultiSendsToAll(t *testing.T) {
	a, b := &fakeNotifier{err: io.EOF}, &fakeNotifier{}
	err := Multi{a, b}.Notify(t.Context(), "s", "t")
	if err == nil || a.count() != 1 || b.count() != 1 {
		t.Fatalf("multi: %v, %d, %d", err, a.count(), b.count())
	}
}
