package redact_test

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/Coreychen4444/go-reliability-patterns/redact"
)

func ExampleNewWriter() {
	h := slog.NewJSONHandler(redact.NewWriter(os.Stdout, nil), &slog.HandlerOptions{
		// Drop the timestamp so the example output is stable.
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
			return a
		},
	})
	log := slog.New(h)
	log.Info("login failed", "user", "bob", "password", "hunter2", "phone", "+65 9123 4567")
	log.Info("upstream call", "url", "https://api.example.com/v1/me?access_token=abc123&page=2")
	// Output:
	// {"level":"INFO","msg":"login failed","user":"bob","password":"[REDACTED]","phone":"+65 9*** *567"}
	// {"level":"INFO","msg":"upstream call","url":"https://api.example.com/v1/me?access_token=[REDACTED]&page=2"}
}

func ExampleRedactor_String() {
	r := redact.New()
	fmt.Println(r.String("POST /login user=bob password=hunter2 mobile=91234567"))
	fmt.Println(r.String("dial postgres://app:s3cret@db:5432/main"))
	// Output:
	// POST /login user=bob password=[REDACTED] mobile=91****67
	// dial postgres://app:[REDACTED]@db:5432/main
}
