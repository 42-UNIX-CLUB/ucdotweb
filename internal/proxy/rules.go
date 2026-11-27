package proxy

// The allow-list in force lives in the store, so an administrator's change takes effect
// without a restart. The proxy keeps the list it last loaded and reloads it when the store's
// change counter moves. A request costs two atomic reads when nothing changed.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/42-UNIX-CLUB/ucdotweb/internal/store"
)

type snapshot struct {
	version uint64
	rules   []Rule
}

// Start seeds the store's list from Rules if it was never seeded, and loads it. Calling it
// at startup turns a bad rules file into an error there; without it, the first request does
// the same work and fails closed on an error.
func (p *Proxy) Start() error {
	p.loadMu.Lock()
	defer p.loadMu.Unlock()
	return p.loadLocked()
}

// rules returns the list in force.
func (p *Proxy) rules() ([]Rule, error) {
	if s := p.snap.Load(); s != nil && s.version == store.AllowlistVersion() {
		return s.rules, nil
	}
	p.loadMu.Lock()
	defer p.loadMu.Unlock()
	if s := p.snap.Load(); s != nil && s.version == store.AllowlistVersion() {
		return s.rules, nil // another request reloaded it meanwhile
	}
	if err := p.loadLocked(); err != nil {
		return nil, err
	}
	return p.snap.Load().rules, nil
}

// loadLocked seeds once, then reads the list. On an error the old list is dropped and the
// next request tries again, so a failed reload never keeps a removed host allowed.
func (p *Proxy) loadLocked() error {
	if !p.seeded {
		seed, err := ValidateRules(p.Rules)
		if err != nil {
			p.snap.Store(nil)
			return fmt.Errorf("proxy: the starting rules: %w", err)
		}
		if _, err := p.DB.SeedAllowlist(toStore(seed)); err != nil {
			p.snap.Store(nil)
			return err
		}
		p.seeded = true
	}
	v := store.AllowlistVersion() // read before the rows: a change after this moves it again
	rows, err := p.DB.AllowRules()
	if err != nil {
		p.snap.Store(nil)
		return err
	}
	rs := make([]Rule, 0, len(rows))
	for _, r := range rows {
		rs = append(rs, Rule{Host: r.Host, Prefixes: r.Prefixes, Git: r.Git, Releases: r.Releases})
	}
	p.snap.Store(&snapshot{version: v, rules: rs})
	return nil
}

func toStore(rs []Rule) []store.AllowRule {
	out := make([]store.AllowRule, 0, len(rs))
	for _, r := range rs {
		out = append(out, store.AllowRule{Host: r.Host, Prefixes: r.Prefixes, Git: r.Git, Releases: r.Releases})
	}
	return out
}

// ToStore turns a checked rule into the store's form.
func (r Rule) ToStore() store.AllowRule { return toStore([]Rule{r})[0] }

// Limits on one rule.
const (
	MaxPrefixes  = 16
	MaxPrefixLen = 200
)

// Names that only mean something inside a network, or are reserved and never public.
var privateSuffixes = []string{"localhost", "local", "localdomain", "internal", "intranet", "lan", "home",
	"corp", "private", "home.arpa", "arpa", "test", "invalid", "example", "onion", "alt"}

// ValidateHost accepts a plain public DNS name in lowercase: letters, digits, hyphens and
// dots, at least two labels, no scheme, port, path, wildcard, trailing dot or IP literal.
func ValidateHost(h string) error {
	if h == "" || len(h) > 253 {
		return errors.New("the host must be 1 to 253 characters")
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return errors.New("the host may hold only lowercase letters, digits, hyphens and dots (no scheme, port, path or wildcard)")
		}
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return errors.New("the host must be a full name with a dot, such as deb.debian.org")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return errors.New("each part of the host must be 1 to 63 characters")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("a part of the host cannot start or end with a hyphen")
		}
	}
	tld := labels[len(labels)-1]
	if strings.Trim(tld, "0123456789") == "" {
		return errors.New("IP addresses are not allowed, only names")
	}
	if len(tld) < 2 {
		return errors.New("the last part of the host is too short")
	}
	for _, s := range privateSuffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return fmt.Errorf("names under .%s are not public", s)
		}
	}
	return nil
}

// validPrefix accepts a path prefix that starts with "/" and could match a request the proxy
// lets through: no dot segments, no encoded dot, slash or backslash, no query or fragment.
func validPrefix(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("the path prefix %q must start with /", p)
	}
	if len(p) > MaxPrefixLen {
		return fmt.Errorf("a path prefix is at most %d characters", MaxPrefixLen)
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~/+:@=,%", c) >= 0
		if !ok {
			return fmt.Errorf("the path prefix %q holds a character that is not allowed", p)
		}
		if c == '%' && (i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2])) {
			return fmt.Errorf("the path prefix %q has a broken %% escape", p)
		}
	}
	if badPath(p) || strings.HasSuffix(p, "/.") || strings.Contains(p, "//") {
		return fmt.Errorf("the path prefix %q has dot segments, an empty segment or an encoded slash, dot or backslash", p)
	}
	return nil
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// ValidateRule checks one rule as an administrator or a rules file gives it.
func ValidateRule(r Rule) error {
	if err := ValidateHost(r.Host); err != nil {
		return err
	}
	if len(r.Prefixes) > MaxPrefixes {
		return fmt.Errorf("a rule has at most %d path prefixes", MaxPrefixes)
	}
	for _, p := range r.Prefixes {
		if err := validPrefix(p); err != nil {
			return err
		}
	}
	if len(r.Prefixes) == 0 && !r.Git && !r.Releases {
		return errors.New("the rule allows nothing: give a path prefix, git or releases")
	}
	return nil
}

// ValidateRules checks a whole list and refuses a host given twice.
func ValidateRules(rs []Rule) ([]Rule, error) {
	seen := map[string]bool{}
	for _, r := range rs {
		if err := ValidateRule(r); err != nil {
			return nil, fmt.Errorf("%s: %w", r.Host, err)
		}
		if seen[r.Host] {
			return nil, fmt.Errorf("%s: the host is listed twice", r.Host)
		}
		seen[r.Host] = true
	}
	return rs, nil
}
