package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestRedactText(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"key=value", "password=hunter2", "password=[REDACTED]"},
		{"logfmt quoted", `level=info msg="login" password="hunter 2" user=bob`, `level=info msg="login" password="[REDACTED]" user=bob`},
		{"single quoted", `api_key='abc123'`, `api_key='[REDACTED]'`},
		{"upper case key", "PASSWORD=x", "PASSWORD=[REDACTED]"},
		{"key contains keyword", "db_password=x retries=3", "db_password=[REDACTED] retries=3"},
		{"header", "X-Api-Key: abc123", "X-Api-Key: [REDACTED]"},
		{"query param", "GET /callback?code=1&access_token=abc.def&state=xyz", "GET /callback?code=1&access_token=[REDACTED]&state=xyz"},
		{"bearer header", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig", "Authorization: Bearer [REDACTED]"},
		{"basic header", "authorization: Basic dXNlcjpwYXNz", "authorization: Basic [REDACTED]"},
		{"bare bearer", "retrying with bearer abc.123 now", "retrying with bearer [REDACTED] now"},
		{"url credentials", "dial postgres://app:s3cret@db:5432/main failed", "dial postgres://app:[REDACTED]@db:5432/main failed"},
		{"embedded JSON", `body={"password":"hunter2","user":"bob"}`, `body={"password":"[REDACTED]","user":"bob"}`},
		{"international phone", "sms sent to +65 9123 4567", "sms sent to +65 9*** *567"},
		{"long international phone", "otp to +8613812345678 ok", "otp to +861******5678 ok"},
		{"phone key", "mobile=91234567", "mobile=91****67"},
		{"several lines", "password=a\nuser=bob\ntoken=b\n", "password=[REDACTED]\nuser=bob\ntoken=[REDACTED]\n"},
		{"unicode case folding", "paſſword=x", "paſſword=[REDACTED]"},
		{"spaces around =", "password = hunter2", "password = [REDACTED]"},
		{"empty value", "password= user=bob", "password= user=bob"},
		{"already masked", "Authorization: Bearer [REDACTED]", "Authorization: Bearer [REDACTED]"},

		// Left alone on purpose: without a '+' or a phone key, a long number
		// is indistinguishable from an ID or a timestamp.
		{"bare number", "order 1234567890123 at 2026-10-20T08:00:00+08:00 took 15ms", "order 1234567890123 at 2026-10-20T08:00:00+08:00 took 15ms"},
		{"clean line", "request completed status=200 path=/v1/orders", "request completed status=200 path=/v1/orders"},

		// Over-redaction is the chosen failure mode: a keyword followed by ':'
		// is treated as a key even in prose.
		{"prose false positive", "refresh token: expired", "refresh token: [REDACTED]"},
	}
	r := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.String(tt.in); got != tt.want {
				t.Errorf("String(%q)\n got: %q\nwant: %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRedactJSON(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"secret string", `{"user":"bob","password":"hunter2"}`, `{"user":"bob","password":"[REDACTED]"}`},
		{"secret number", `{"pin_token":123456}`, `{"pin_token":"[REDACTED]"}`},
		{"no secret in literals", `{"token_valid":true,"api_key":null,"secret":""}`, `{"token_valid":true,"api_key":null,"secret":""}`},
		{"secret object", `{"credentials":{"user":"a","pass":"b"},"ok":1}`, `{"credentials":"[REDACTED]","ok":1}`},
		{"nested key", `{"req":{"headers":{"Authorization":"Bearer x"}}}`, `{"req":{"headers":{"Authorization":"[REDACTED]"}}}`},
		{"whitespace", `{ "password" : "x" }`, `{ "password" : "[REDACTED]" }`},
		{"phone string", `{"phone":"+65 9123 4567"}`, `{"phone":"+65 9*** *567"}`},
		{"phone number becomes string", `{"mobile":6591234567}`, `{"mobile":"659****567"}`},
		{"phone with escapes", `{"phone":"\u0036591234567"}`, `{"phone":"\u003659****567"}`},
		{"free text in value", `{"msg":"login failed: password=hunter2"}`, `{"msg":"login failed: password=[REDACTED]"}`},
		{"JSON inside a string", `{"msg":"body {\"password\":\"hunter2\"}"}`, `{"msg":"body {\"password\":\"[REDACTED]\"}"}`},
		{"array", `["password=x", 1]`, `["password=[REDACTED]", 1]`},
		{
			"ECS record",
			`{"@timestamp":"2026-10-20T08:00:00Z","log.level":"info","message":"sent","user.phone":"91234567","url.query":"token=abc&page=2"}` + "\n",
			`{"@timestamp":"2026-10-20T08:00:00Z","log.level":"info","message":"sent","user.phone":"91****67","url.query":"token=[REDACTED]&page=2"}` + "\n",
		},
	}
	r := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.String(tt.in)
			if got != tt.want {
				t.Errorf("String(%s)\n got: %s\nwant: %s", tt.in, got, tt.want)
			}
			if !json.Valid([]byte(got)) {
				t.Errorf("output is not valid JSON: %s", got)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
		in   string
		want string
	}{
		{"extra secret key", []Option{WithSecretKeys("OTP")}, "otp=123456", "otp=[REDACTED]"},
		{"extra phone key", []Option{WithPhoneKeys("contact_no")}, "contact_no=91234567", "contact_no=91****67"},
		{"phone suffix only", []Option{WithPhoneVisible(0, 2)}, "mobile=91234567", "mobile=******67"},
		{"short number masks at least four", []Option{WithPhoneVisible(3, 4)}, "mobile=123456", "mobile=1****6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.opts...).String(tt.in); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNonASCIIKeyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New with a non-ASCII key did not panic")
		}
	}()
	New(WithSecretKeys("passwört"))
}

func TestVisibleDigits(t *testing.T) {
	tests := []struct {
		n, prefix, suffix int
		wantP, wantS      int
	}{
		{13, 3, 4, 3, 4},
		{11, 3, 4, 3, 4},
		{10, 3, 4, 3, 3},
		{8, 3, 4, 2, 2},
		{5, 3, 4, 0, 1},
		{3, 3, 4, 0, 0},
		{0, 3, 4, 0, 0},
	}
	for _, tt := range tests {
		p, s := visibleDigits(tt.n, tt.prefix, tt.suffix)
		if p != tt.wantP || s != tt.wantS {
			t.Errorf("visibleDigits(%d, %d, %d) = %d, %d; want %d, %d", tt.n, tt.prefix, tt.suffix, p, s, tt.wantP, tt.wantS)
		}
		if tt.n >= 4 && tt.n-p-s < 4 {
			t.Errorf("visibleDigits(%d, ...) masks only %d digits", tt.n, tt.n-p-s)
		}
	}
}

// The secret must not survive in any of these shapes.
func TestNoLeak(t *testing.T) {
	const secret = "Zx9-SECRET-VALUE"
	templates := []string{
		"password=%s",
		"password: %s",
		`password="%s"`,
		"token=%s&page=1",
		"Authorization: Bearer %s",
		"Authorization: %s",
		"https://user:%s@example.com/",
		`{"password":"%s"}`,
		`{"nested":{"client_secret":"%s"}}`,
		`{"msg":"retry with access_token=%s"}`,
		`{"msg":"payload {\"api_key\":\"%s\"}"}`,
		`{"headers":["Authorization: Bearer %s"]}`,
	}
	r := New()
	for _, tmpl := range templates {
		in := strings.ReplaceAll(tmpl, "%s", secret)
		if out := r.String(in); strings.Contains(out, secret) || strings.Contains(out, "SECRET") {
			t.Errorf("secret leaked:\n in: %s\nout: %s", in, out)
		}
	}
}

func TestWriterReportsInputLength(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, nil)
	in := []byte("login password=hunter2\n")
	n, err := w.Write(in)
	if err != nil || n != len(in) {
		t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(in))
	}
	if want := "login password=[REDACTED]\n"; buf.String() != want {
		t.Fatalf("wrote %q, want %q", buf.String(), want)
	}
}

type errWriter struct {
	n   int
	err error
}

func (e errWriter) Write(p []byte) (int, error) { return min(e.n, len(p)), e.err }

func TestWriterErrors(t *testing.T) {
	boom := errors.New("disk full")
	tests := []struct {
		name    string
		w       io.Writer
		in      string
		wantN   int
		wantErr error
	}{
		{"error on redacted line", errWriter{0, boom}, "password=x", 0, boom},
		{"short write on redacted line", errWriter{3, nil}, "password=x", 0, io.ErrShortWrite},
		{"error on clean line passes through", errWriter{2, boom}, "status=200", 2, boom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := NewWriter(tt.w, nil).Write([]byte(tt.in))
			if n != tt.wantN || !errors.Is(err, tt.wantErr) {
				t.Errorf("Write = %d, %v; want %d, %v", n, err, tt.wantN, tt.wantErr)
			}
		})
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func TestWriterConcurrent(t *testing.T) {
	var buf lockedBuffer
	w := NewWriter(&buf, nil)
	const goroutines, lines = 8, 200
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < lines; i++ {
				if i%2 == 0 {
					_, _ = w.Write([]byte(`{"msg":"login","password":"hunter2"}` + "\n"))
				} else {
					_, _ = w.Write([]byte("status=200 path=/v1/orders\n"))
				}
			}
		}()
	}
	wg.Wait()
	out := buf.String()
	if strings.Contains(out, "hunter2") {
		t.Fatal("secret leaked under concurrent writes")
	}
	if got, want := strings.Count(out, "\n"), goroutines*lines; got != want {
		t.Fatalf("got %d lines, want %d", got, want)
	}
}

func TestFastPathDoesNotAllocate(t *testing.T) {
	r := New()
	w := NewWriter(io.Discard, r)
	line := []byte(`{"@timestamp":"2026-10-20T08:00:00Z","log.level":"info","message":"request completed","http.response.status_code":200}` + "\n")
	if n := testing.AllocsPerRun(100, func() { _, _ = w.Write(line) }); n != 0 {
		t.Errorf("Writer.Write on a clean line allocated %v times, want 0", n)
	}
	buf := make([]byte, 0, 1024)
	if n := testing.AllocsPerRun(100, func() { buf = r.Append(buf[:0], line) }); n != 0 {
		t.Errorf("Append on a clean line allocated %v times, want 0", n)
	}
}
