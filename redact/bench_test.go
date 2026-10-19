package redact

import (
	"bytes"
	"io"
	"log/slog"
	"regexp"
	"testing"
)

var benchLines = []struct{ name, line string }{
	{"clean-json", `{"@timestamp":"2026-10-20T08:15:30.123Z","log.level":"info","message":"request completed","service.name":"orders","http.request.method":"GET","url.path":"/v1/orders/8812","http.response.status_code":200,"event.duration":1534000,"trace.id":"4bf92f3577b34da6a3ce929d0e0e4736"}` + "\n"},
	{"clean-text", `2026-10-20T08:15:30.123Z INFO request completed service=orders method=GET path=/v1/orders/8812 status=200 duration=1.534ms trace=4bf92f3577b34da6a3ce929d0e0e4736` + "\n"},
	{"secret-json", `{"@timestamp":"2026-10-20T08:15:30.123Z","log.level":"warn","message":"login failed","service.name":"auth","user.name":"bob","password":"hunter2","user.phone":"+65 9123 4567","trace.id":"4bf92f3577b34da6a3ce929d0e0e4736"}` + "\n"},
	{"secret-text", `2026-10-20T08:15:30.123Z WARN upstream call failed url=https://api.example.com/v1/accounts?access_token=abc.def.ghi&page=2 Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig trace=4bf92f3577b34da6a3ce929d0e0e4736` + "\n"},
}

// BenchmarkRedact compares three ways to redact the same line:
//
//   - fast-path: the Redactor as shipped (keyword check, then merged regexp
//     or JSON walker);
//   - merged-regexp: the merged regexp on every line, no fast path;
//   - per-rule-regexps: one regexp per rule, applied one after another, the
//     naive version.
func BenchmarkRedact(b *testing.B) {
	r := New()
	seq := perRuleRegexps(r)
	variants := []struct {
		name string
		fn   func(dst, src []byte) []byte
	}{
		{"fast-path", r.Append},
		{"merged-regexp", r.appendText},
		{"per-rule-regexps", seq},
	}
	for _, in := range benchLines {
		src := []byte(in.line)
		if !bytes.Equal(r.appendText(nil, src), seq(nil, src)) {
			b.Fatalf("%s: merged and per-rule regexps disagree", in.name)
		}
		for _, v := range variants {
			b.Run(in.name+"/"+v.name, func(b *testing.B) {
				buf := make([]byte, 0, 1024)
				b.SetBytes(int64(len(src)))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					buf = v.fn(buf[:0], src)
				}
			})
		}
	}
}

// perRuleRegexps returns a redactor that compiles each rule on its own and
// applies them in sequence, re-scanning the line once per rule.
func perRuleRegexps(r *Redactor) func(dst, src []byte) []byte {
	type compiled struct {
		re *regexp.Regexp
		ru *rule
	}
	var rules []compiled
	for i := range r.rules {
		rules = append(rules, compiled{regexp.MustCompile("(?i)(" + r.rules[i].pattern + ")"), &r.rules[i]})
	}
	return func(dst, src []byte) []byte {
		cur := src
		for _, c := range rules {
			var out []byte
			last := 0
			for _, m := range c.re.FindAllSubmatchIndex(cur, -1) {
				out = append(out, cur[last:m[0]]...)
				out = r.applyRule(out, cur, m, c.ru, 1)
				last = m[1]
			}
			cur = append(out, cur[last:]...)
		}
		return append(dst, cur...)
	}
}

// BenchmarkSlog measures the cost of the Writer behind log/slog's JSON
// handler for a record with no secrets, the common case.
func BenchmarkSlog(b *testing.B) {
	for _, tc := range []struct {
		name string
		w    io.Writer
	}{
		{"plain", io.Discard},
		{"redacting-writer", NewWriter(io.Discard, nil)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			log := slog.New(slog.NewJSONHandler(tc.w, nil))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				log.Info("request completed", "method", "GET", "path", "/v1/orders/8812", "status", 200)
			}
		})
	}
}
