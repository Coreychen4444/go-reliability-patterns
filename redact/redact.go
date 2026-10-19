// Package redact masks credentials and personal data in log output before it
// leaves the process.
//
// A Redactor works line by line. Every line first goes through a cheap fast
// path: it is lower-cased into a scratch buffer and searched for the literals
// that each rule needs (for example "password", "bearer", or a '+' followed by
// a digit). Most log lines contain none of them and pass through untouched and
// without allocating. A line that does contain one is redacted either by a
// JSON-aware walker, when the line is a JSON document, or by a single merged
// regular expression, when it is free text.
package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Mask replaces secret values.
const Mask = "[REDACTED]"

// DefaultSecretKeys are the key names treated as secrets. A key matches when it
// contains one of them, ignoring case, so "db_password" and "X-Api-Key" match.
var DefaultSecretKeys = []string{
	"password", "passwd", "pwd", "secret", "token",
	"apikey", "api_key", "api-key",
	"accesskey", "access_key", "access-key",
	"privatekey", "private_key", "private-key",
	"authorization", "credential", "signature", "cvv",
	"sessionid", "session_id", "session-id",
}

// DefaultPhoneKeys are the key names whose values are masked as phone numbers.
var DefaultPhoneKeys = []string{"phone", "mobile", "msisdn"}

// An Option configures a Redactor.
type Option func(*config)

type config struct {
	secretKeys []string
	phoneKeys  []string
	keepPrefix int
	keepSuffix int
}

// WithSecretKeys adds key names to treat as secrets. Names must be ASCII.
func WithSecretKeys(keys ...string) Option {
	return func(c *config) { c.secretKeys = append(c.secretKeys, keys...) }
}

// WithPhoneKeys adds key names whose values are masked as phone numbers.
// Names must be ASCII.
func WithPhoneKeys(keys ...string) Option {
	return func(c *config) { c.phoneKeys = append(c.phoneKeys, keys...) }
}

// WithPhoneVisible sets how many leading and trailing digits of a phone number
// stay visible. The default is 3 and 4. Short numbers show fewer digits: at
// least four digits are always masked.
func WithPhoneVisible(prefix, suffix int) Option {
	return func(c *config) { c.keepPrefix, c.keepSuffix = max(prefix, 0), max(suffix, 0) }
}

// A Redactor masks secrets in log lines. It is safe for concurrent use.
type Redactor struct {
	re         *regexp.Regexp
	rules      []rule
	secretKeys [][]byte
	phoneKeys  [][]byte
	keepPrefix int
	keepSuffix int
	keywords   *keywordSet // every rule's trigger keywords, for the fast path
}

// A rule is one alternative of the merged regexp.
type rule struct {
	name    string
	pattern string
	targets []target // inner groups to rewrite, in group order
	trigger trigger  // literals the pattern cannot match without
	base    int      // index of the rule's wrapper group in the merged regexp
}

// A target is an inner capture group whose text is rewritten.
type target struct {
	group int
	// digits masks the group as a phone number instead of replacing it with
	// Mask, if it holds minDigits to maxDigits digits. Counting here rather
	// than with {m,n} in the pattern keeps the regexp program small: Go's
	// regexp has no DFA, so its cost grows with program size.
	digits               bool
	minDigits, maxDigits int
}

// A trigger is the fast-path check for a rule. It must hold for every input on
// which the rule changes something, otherwise the fast path would skip real
// secrets; FuzzRedact checks this by comparing the fast and slow paths.
type trigger struct {
	any      [][]byte // at least one must occur (checked together, see keywordSet)
	all      [][]byte // every one must occur
	phoneRun int      // a '+' followed by at least this many digits, possibly separated, must occur
}

// New returns a Redactor with the default key lists and any extra options.
func New(opts ...Option) *Redactor {
	c := config{
		secretKeys: append([]string(nil), DefaultSecretKeys...),
		phoneKeys:  append([]string(nil), DefaultPhoneKeys...),
		keepPrefix: 3,
		keepSuffix: 4,
	}
	for _, o := range opts {
		o(&c)
	}
	r := &Redactor{
		secretKeys: asciiLower(c.secretKeys),
		phoneKeys:  asciiLower(c.phoneKeys),
		keepPrefix: c.keepPrefix,
		keepSuffix: c.keepSuffix,
	}
	r.rules = buildRules(r.secretKeys, r.phoneKeys)
	r.re = compile(r.rules)
	var words [][]byte
	for _, ru := range r.rules {
		words = append(words, ru.trigger.any...)
	}
	r.keywords = newKeywordSet(words)
	return r
}

// Value characters for an unquoted secret. Quotes and backslashes are excluded
// so a replacement never splits an escape sequence, and brackets are excluded
// so the mask itself is never matched again.
const bareValue = `[^\s"'\\,;&<>{}\[\]]+`

func buildRules(secretKeys, phoneKeys [][]byte) []rule {
	key := func(words [][]byte) string {
		quoted := make([]string, len(words))
		for i, w := range words {
			quoted[i] = regexp.QuoteMeta(string(w))
		}
		return `[\w.-]*(?:` + strings.Join(quoted, "|") + `)[\w.-]*`
	}
	// The separator allows a closing quote, so `"password":"x"` embedded in
	// free text and `\"password\":\"x\"` inside a JSON string both match.
	// Spaces may follow ':' but follow '=' only when they also precede it, so
	// "password= user=bob" is an empty password, not the password "user=bob".
	const sep = `\\?["']?(?:\s+=\s+|=|\s*:\s*)`
	// An already-masked value is consumed without a capture, which keeps
	// "Authorization: Bearer [REDACTED]" from being redacted a second time.
	masked := regexp.QuoteMeta(Mask)
	return []rule{
		{
			// password=x, token: "x y", api_key='x', \"secret\":\"x\",
			// Authorization: Bearer x
			name: "key-value",
			pattern: `(` + key(secretKeys) + `)(` + sep + `)(?:` +
				`"([^"\\\n]*)"` + // 3: double-quoted
				`|\\"((?:[^"\\]|\\[^"])*)\\"` + // 4: escaped double-quoted, inside a JSON string
				`|'([^'\\\n]*)'` + // 5: single-quoted
				`|(?:\\?["'])?(?:(?:bearer|basic|digest|token)\s+)?(?:` + masked + `|(` + bareValue + `)))`, // 6: bare, after an optional auth scheme
			targets: []target{{group: 3}, {group: 4}, {group: 5}, {group: 6}},
			trigger: trigger{any: secretKeys},
		},
		{
			// phone=+65 9123 4567, "mobile":"91234567"
			name:    "phone-key-value",
			pattern: `(` + key(phoneKeys) + `)(` + sep + `(?:\\?["'])?)(\+?\(?\d(?:[ .()-]{0,2}\d)+)`,
			targets: []target{{group: 3, digits: true, minDigits: 6, maxDigits: 19}},
			trigger: trigger{any: phoneKeys},
		},
		{
			// postgres://user:pass@host
			name:    "url-credentials",
			pattern: `\b([a-z][a-z0-9+.-]*://[^\s/:@"'\\]+):([^\s/@"'\\]+)@`,
			targets: []target{{group: 2}},
			trigger: trigger{all: [][]byte{[]byte("://"), []byte("@")}},
		},
		{
			// a bearer token outside a key-value pair
			name:    "bearer",
			pattern: `\b(bearer)\s+([a-z0-9._~+/-]+=*)`,
			targets: []target{{group: 2}},
			trigger: trigger{any: [][]byte{[]byte("bearer")}},
		},
		{
			// an international number anywhere: +65 9123 4567. Numbers without
			// a '+' or a phone key are left alone; they are indistinguishable
			// from IDs and timestamps.
			name:    "phone-international",
			pattern: `(\+\d(?:[ .()-]{0,2}\d)+)`,
			targets: []target{{group: 1, digits: true, minDigits: 8, maxDigits: 15}}, // E.164 allows up to 15
			trigger: trigger{phoneRun: 8},
		},
	}
}

// compile merges the rules into one case-insensitive alternation, so a line is
// scanned once rather than once per rule, and records where each rule's groups
// start.
func compile(rules []rule) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?i)")
	group := 1
	for i := range rules {
		if i > 0 {
			b.WriteByte('|')
		}
		b.WriteString("(" + rules[i].pattern + ")")
		rules[i].base = group
		group += 1 + regexp.MustCompile(rules[i].pattern).NumSubexp()
	}
	return regexp.MustCompile(b.String())
}

func asciiLower(words []string) [][]byte {
	out := make([][]byte, 0, len(words))
	for _, w := range words {
		for i := 0; i < len(w); i++ {
			if w[i] >= 0x80 {
				panic(fmt.Sprintf("redact: key %q is not ASCII", w))
			}
		}
		if w != "" {
			out = append(out, []byte(strings.ToLower(w)))
		}
	}
	return out
}

// Append appends the redacted form of src to dst and returns the result.
func (r *Redactor) Append(dst, src []byte) []byte {
	if !r.mayContain(src) {
		return append(dst, src...)
	}
	return r.appendLines(dst, src, false)
}

// String returns the redacted form of s.
func (r *Redactor) String(s string) string {
	b := []byte(s)
	if !r.mayContain(b) {
		return s
	}
	return string(r.appendLines(nil, b, false))
}

// appendLines redacts src line by line. With slow set it skips every fast-path
// check, which tests use as the reference result.
func (r *Redactor) appendLines(dst, src []byte, slow bool) []byte {
	for len(src) > 0 {
		n := bytes.IndexByte(src, '\n') + 1
		if n == 0 {
			n = len(src)
		}
		dst = r.appendLine(dst, src[:n], slow)
		src = src[n:]
	}
	return dst
}

func (r *Redactor) appendLine(dst, line []byte, slow bool) []byte {
	if !slow && !r.mayContain(line) {
		return append(dst, line...)
	}
	if json.Valid(line) { // fails on the first byte for most free text
		return r.appendJSON(dst, line, slow)
	}
	return r.appendText(dst, line)
}

// appendText applies the merged regexp to free text.
func (r *Redactor) appendText(dst, src []byte) []byte {
	last := 0
	for _, m := range r.re.FindAllSubmatchIndex(src, -1) {
		ru := r.ruleFor(m)
		dst = append(dst, src[last:m[0]]...)
		dst = r.applyRule(dst, src, m, ru, ru.base)
		last = m[1]
	}
	return append(dst, src[last:]...)
}

func (r *Redactor) ruleFor(m []int) *rule {
	for i := range r.rules {
		if m[2*r.rules[i].base] >= 0 {
			return &r.rules[i]
		}
	}
	panic("redact: match without a rule") // unreachable: every alternative is a rule
}

// applyRule writes one match to dst, rewriting the rule's target groups. base
// is the index of the group that wraps the rule's pattern in m.
func (r *Redactor) applyRule(dst, src []byte, m []int, ru *rule, base int) []byte {
	pos, end := m[2*base], m[2*base+1]
	for _, t := range ru.targets {
		s, e := m[2*(base+t.group)], m[2*(base+t.group)+1]
		if s < 0 || s == e {
			continue
		}
		if t.digits && !digitCountIn(src[s:e], t.minDigits, t.maxDigits) {
			continue // not a phone number after all; leave it
		}
		dst = append(dst, src[pos:s]...)
		if t.digits {
			dst = r.appendMaskedDigits(dst, src[s:e])
		} else {
			dst = append(dst, Mask...)
		}
		pos = e
	}
	return append(dst, src[pos:end]...)
}

// appendMaskedDigits masks the middle digits of a phone number and keeps its
// separators. A '*' counts as an already-masked digit, so masking is
// idempotent. JSON escape sequences are copied unchanged so the digits inside
// \u0039 are never touched.
func (r *Redactor) appendMaskedDigits(dst, s []byte) []byte {
	slots := 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\':
			i += escapeLen(s, i) - 1
		case isDigit(s[i]) || s[i] == '*':
			slots++
		}
	}
	prefix, suffix := visibleDigits(slots, r.keepPrefix, r.keepSuffix)
	slot := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			n := escapeLen(s, i)
			dst = append(dst, s[i:i+n]...)
			i += n - 1
			continue
		case isDigit(c) || c == '*':
			if slot >= prefix && slot < slots-suffix {
				c = '*'
			}
			slot++
		}
		dst = append(dst, c)
	}
	return dst
}

// visibleDigits shrinks the visible prefix and suffix until at least four of n
// digits are masked.
func visibleDigits(n, prefix, suffix int) (int, int) {
	const minMasked = 4
	for prefix+suffix > 0 && prefix+suffix > n-minMasked {
		if prefix >= suffix {
			prefix--
		} else {
			suffix--
		}
	}
	return prefix, suffix
}

// escapeLen returns the length of the escape sequence starting at s[i]. It is
// 1 for a lone trailing backslash.
func escapeLen(s []byte, i int) int {
	switch {
	case i+1 >= len(s):
		return 1
	case s[i+1] == 'u' && i+6 <= len(s):
		return 6
	default:
		return 2
	}
}

// mayContain reports whether any rule could match src. It is the fast path:
// one lower-casing pass and a few substring searches, with no allocation for
// lines up to 1 KiB.
func (r *Redactor) mayContain(src []byte) bool {
	if len(src) > 1024 {
		return r.mayContainLarge(src)
	}
	var stack [1024]byte
	return r.anyTrigger(foldLower(stack[:0], src))
}

func (r *Redactor) mayContainLarge(src []byte) bool {
	bp := scratchPool.Get().(*[]byte)
	lower := foldLower((*bp)[:0], src)
	ok := r.anyTrigger(lower)
	if cap(lower) <= maxPooled {
		*bp = lower[:0]
		scratchPool.Put(bp)
	}
	return ok
}

func (r *Redactor) anyTrigger(lower []byte) bool {
	if r.keywords.in(lower) {
		return true
	}
	for i := range r.rules {
		t := &r.rules[i].trigger
		if t.phoneRun > 0 && hasPhoneRun(lower, t.phoneRun) {
			return true
		}
		if len(t.all) > 0 && containsAll(lower, t.all) {
			return true
		}
	}
	return false
}

const maxPooled = 64 << 10

var scratchPool = sync.Pool{New: func() any { return new([]byte) }}

// foldLower appends src to dst with ASCII letters lower-cased. It also folds
// the only two non-ASCII runes that Go's (?i) matching treats as ASCII
// letters: U+017F (ſ, matches s) and U+212A (Kelvin sign, matches k).
// Without this the fast path would skip "paſſword=x", which the regexp
// matches.
func foldLower(dst, src []byte) []byte {
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case 'A' <= c && c <= 'Z':
			c += 'a' - 'A'
		case c == 0xC5 && i+1 < len(src) && src[i+1] == 0xBF:
			c = 's'
			i++
		case c == 0xE2 && i+2 < len(src) && src[i+1] == 0x84 && src[i+2] == 0xAA:
			c = 'k'
			i += 2
		}
		dst = append(dst, c)
	}
	return dst
}

func containsAny(b []byte, words [][]byte) bool {
	for _, w := range words {
		if bytes.Contains(b, w) {
			return true
		}
	}
	return false
}

func containsAll(b []byte, words [][]byte) bool {
	for _, w := range words {
		if !bytes.Contains(b, w) {
			return false
		}
	}
	return true
}

// hasPhoneRun reports whether a '+' is followed by at least min digits, with
// only phone separators between them. "+08:00" in a timestamp is not, so the
// timezone offset in most log lines does not defeat the fast path.
func hasPhoneRun(b []byte, min int) bool {
	for {
		i := bytes.IndexByte(b, '+')
		if i < 0 {
			return false
		}
		b = b[i+1:]
		n := 0
		for _, c := range b {
			if isDigit(c) {
				n++
			} else if !isPhoneSep(c) {
				break
			}
		}
		if n >= min {
			return true
		}
	}
}

func digitCountIn(s []byte, min, max int) bool {
	n := 0
	for _, c := range s {
		if isDigit(c) {
			n++
		}
	}
	return min <= n && n <= max
}

func isPhoneSep(c byte) bool {
	return c == ' ' || c == '.' || c == '(' || c == ')' || c == '-'
}

// keywordSet finds any of a set of lower-case ASCII keywords in one pass over
// the input. A bitmap of each keyword's first two bytes rules out almost every
// position, so the byte comparison runs only where a keyword could start.
// Searching for 25 keywords one bytes.Contains at a time costs 25 passes.
type keywordSet struct {
	bigram  [256][4]uint64 // bit (a, b) set if some keyword starts with ab
	byFirst [256][][]byte
	single  [256]bool // one-byte keywords
}

func newKeywordSet(words [][]byte) *keywordSet {
	k := &keywordSet{}
	for _, w := range words {
		switch len(w) {
		case 0:
		case 1:
			k.single[w[0]] = true
		default:
			k.bigram[w[0]][w[1]>>6] |= 1 << (w[1] & 63)
			k.byFirst[w[0]] = append(k.byFirst[w[0]], w)
		}
	}
	return k
}

func (k *keywordSet) in(b []byte) bool {
	for i := 0; i < len(b); i++ {
		c := b[i]
		if k.single[c] {
			return true
		}
		if i+1 == len(b) {
			break
		}
		d := b[i+1]
		if k.bigram[c][d>>6]&(1<<(d&63)) == 0 {
			continue
		}
		for _, w := range k.byFirst[c] {
			if bytes.HasPrefix(b[i:], w) {
				return true
			}
		}
	}
	return false
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }
