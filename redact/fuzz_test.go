package redact

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzRedact checks three properties on arbitrary input:
//
//  1. The fast path never changes the result. Skipping a line because no
//     trigger matched must give the same output as running every rule on it,
//     so a trigger can never hide a secret the regexp would have caught.
//  2. Redaction is idempotent, so logs that pass through two redactors (the
//     app and a log shipper) are not mangled further.
//  3. A valid single-line JSON document stays valid JSON.
func FuzzRedact(f *testing.F) {
	seeds := []string{
		"password=hunter2",
		`level=info password="hunter 2" user=bob`,
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig",
		"dial postgres://app:s3cret@db:5432/main",
		"sms sent to +65 9123 4567",
		"mobile=91234567",
		"paſſword=x",
		"to\u212aen=x",
		`{"user":"bob","password":"hunter2","phone":6591234567}`,
		`{"msg":"body {\"password\":\"hunter2\"}","n":[1,2,{"api_key":{"a":1}}]}`,
		`{"phone":"\u0036591234567"}`,
		"-1e+12345678",
		"at 2026-10-20T08:00:00+08:00 call +65 9123 4567",
		"status=200 path=/v1/orders\nsecret=x\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	r := New()
	f.Fuzz(func(t *testing.T, in string) {
		src := []byte(in)
		fast := r.Append(nil, src)
		slow := r.appendLines(nil, src, true)
		if !bytes.Equal(fast, slow) {
			t.Fatalf("fast path changed the result\n  in: %q\nfast: %q\nslow: %q", in, fast, slow)
		}
		if again := r.Append(nil, fast); !bytes.Equal(again, fast) {
			t.Fatalf("not idempotent\n   in: %q\nonce: %q\ntwice: %q", in, fast, again)
		}
		if !bytes.Contains(src, []byte("\n")) && json.Valid(src) && !json.Valid(fast) {
			t.Fatalf("valid JSON became invalid\n in: %s\nout: %s", in, fast)
		}
	})
}
