package safety

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Notifier tells the administrators about a suspension.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, subject, text string) error
}

// Multi sends to every notifier and joins their errors.
type Multi []Notifier

// Name lists the members.
func (m Multi) Name() string { return strings.Join(names(m), ",") }

// Notify sends to all, even when one fails.
func (m Multi) Notify(ctx context.Context, subject, text string) error {
	var errs []error
	for _, n := range m {
		if err := n.Notify(ctx, subject, text); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func names(n Notifier) []string {
	switch v := n.(type) {
	case nil:
		return []string{}
	case Multi:
		out := []string{}
		for _, x := range v {
			out = append(out, names(x)...)
		}
		return out
	}
	return []string{n.Name()}
}

// ---- webhook ----

// Webhook posts {"<Field>": "<subject>\n<text>"} as JSON to a chat's incoming webhook.
// Field "content" is Discord's format; "text" is Slack's (Mattermost and Matrix hookshot
// accept it too).
type Webhook struct {
	URL    string
	Field  string // "content" or "text"
	Client *http.Client
}

// Name is "webhook".
func (h *Webhook) Name() string { return "webhook" }

// Notify posts the message. The URL is a secret (it carries the chat's token), so errors
// never include it.
func (h *Webhook) Notify(ctx context.Context, subject, text string) error {
	msg := subject + "\n" + text
	if len(msg) > 1900 { // Discord refuses more than 2000 characters
		msg = strings.ToValidUTF8(msg[:1900], "")
	}
	body, _ := json.Marshal(map[string]string{h.Field: msg})
	req, err := http.NewRequestWithContext(ctx, "POST", h.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("bad webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ucdotweb-safety")
	c := h.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("webhook post failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook answered %d", resp.StatusCode)
	}
	return nil
}

// ---- e-mail ----

// Mail sends through an SMTP server on the submission port, always with STARTTLS. Without
// STARTTLS it sends nothing, so credentials never travel in clear.
type Mail struct {
	Host     string
	Port     int
	From     string
	To       []string
	User     string // empty: no AUTH
	Password string
	RootCAs  *x509.CertPool // nil: the system's; tests set their own
	Now      func() time.Time
}

// Name is "email".
func (m *Mail) Name() string { return "email" }

// ErrNoStartTLS means the server does not offer STARTTLS; nothing was sent.
var ErrNoStartTLS = errors.New("the mail server does not offer STARTTLS; nothing sent")

// Notify sends one plain text message to every recipient.
func (m *Mail) Notify(ctx context.Context, subject, text string) error {
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(m.Host, strconv.Itoa(m.Port)))
	if err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, m.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Hello("localhost"); err != nil {
		return err
	}
	if ok, _ := c.Extension("STARTTLS"); !ok {
		return ErrNoStartTLS
	}
	if err := c.StartTLS(&tls.Config{ServerName: m.Host, RootCAs: m.RootCAs, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("starttls: %w", err)
	}
	if m.User != "" {
		if err := c.Auth(smtp.PlainAuth("", m.User, m.Password, m.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(m.From); err != nil {
		return err
	}
	for _, to := range m.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(m.message(subject, text)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func oneLine(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }

func (m *Mail) message(subject, text string) []byte {
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", oneLine(m.From))
	fmt.Fprintf(&b, "To: %s\r\n", oneLine(strings.Join(m.To, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", oneLine(subject))
	fmt.Fprintf(&b, "Date: %s\r\n", now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n"))
	b.WriteString("\r\n")
	return []byte(b.String())
}

// ---- configuration ----

// NotifierFromEnv builds the notifiers from these variables. Each is off when its first
// variable is unset; the result is nil when both are off.
//
//	UCDOTWEB_WEBHOOK_URL_FILE  a file holding the chat's incoming webhook URL (https)
//	UCDOTWEB_WEBHOOK_FORMAT    "content" (Discord) or "text" (Slack, Mattermost, Matrix hookshot);
//	                           default: "content" for discord.com and discordapp.com, else "text"
//	UCDOTWEB_SMTP_HOST         the mail server
//	UCDOTWEB_SMTP_PORT         default 587 (STARTTLS is required on any port)
//	UCDOTWEB_SMTP_FROM         the sender address
//	UCDOTWEB_SMTP_TO           comma-separated recipients
//	UCDOTWEB_SMTP_AUTH_FILE    optional: a file with the user name on line 1 and the password on line 2
func NotifierFromEnv(getenv func(string) string) (Notifier, error) {
	var out Multi
	if p := getenv("UCDOTWEB_WEBHOOK_URL_FILE"); p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("UCDOTWEB_WEBHOOK_URL_FILE: %v", err)
		}
		u, err := url.Parse(strings.TrimSpace(string(raw)))
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, errors.New("UCDOTWEB_WEBHOOK_URL_FILE must hold an https URL")
		}
		field := getenv("UCDOTWEB_WEBHOOK_FORMAT")
		switch field {
		case "":
			field = "text"
			if h := strings.ToLower(u.Hostname()); h == "discord.com" || h == "discordapp.com" {
				field = "content"
			}
		case "content", "text":
		default:
			return nil, errors.New(`UCDOTWEB_WEBHOOK_FORMAT must be "content" or "text"`)
		}
		out = append(out, &Webhook{URL: u.String(), Field: field})
	}
	if host := getenv("UCDOTWEB_SMTP_HOST"); host != "" {
		m := &Mail{Host: host, Port: 587, From: getenv("UCDOTWEB_SMTP_FROM")}
		if v := getenv("UCDOTWEB_SMTP_PORT"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 65535 {
				return nil, errors.New("UCDOTWEB_SMTP_PORT: bad port")
			}
			m.Port = n
		}
		for _, t := range strings.Split(getenv("UCDOTWEB_SMTP_TO"), ",") {
			if t = strings.TrimSpace(t); t != "" {
				m.To = append(m.To, t)
			}
		}
		if m.From == "" || len(m.To) == 0 {
			return nil, errors.New("UCDOTWEB_SMTP_HOST is set: UCDOTWEB_SMTP_FROM and UCDOTWEB_SMTP_TO are needed too")
		}
		if strings.ContainsAny(m.From+strings.Join(m.To, ""), "\r\n") {
			return nil, errors.New("UCDOTWEB_SMTP_FROM and UCDOTWEB_SMTP_TO cannot contain line breaks")
		}
		if p := getenv("UCDOTWEB_SMTP_AUTH_FILE"); p != "" {
			raw, err := os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("UCDOTWEB_SMTP_AUTH_FILE: %v", err)
			}
			lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
			if len(lines) < 2 || lines[0] == "" || lines[1] == "" {
				return nil, errors.New("UCDOTWEB_SMTP_AUTH_FILE: the user name on line 1 and the password on line 2")
			}
			m.User, m.Password = lines[0], lines[1]
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
