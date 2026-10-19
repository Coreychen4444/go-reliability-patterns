package sqlstore

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The statements are checked here; examples/sqlite runs them against a real
// SQLite database.
func TestStatements(t *testing.T) {
	tests := []struct {
		dialect     Dialect
		wantInsert  string
		placeholder string
	}{
		{SQLite, "ON CONFLICT (idempotency_key) DO NOTHING", "?"},
		{Postgres, "ON CONFLICT (idempotency_key) DO NOTHING", "$1"},
		{MySQL, "INSERT IGNORE INTO processed_messages", "?"},
	}
	for _, tt := range tests {
		s, err := New(nil, tt.dialect, "processed_messages")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(s.insert, tt.wantInsert) || !strings.Contains(s.insert, tt.placeholder) {
			t.Errorf("dialect %d: insert %q, want %q with %q placeholders", tt.dialect, s.insert, tt.wantInsert, tt.placeholder)
		}
		if !strings.Contains(s.purge, tt.placeholder) {
			t.Errorf("dialect %d: purge %q, want %q placeholders", tt.dialect, s.purge, tt.placeholder)
		}
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	tests := []struct {
		name    string
		dialect Dialect
		table   string
	}{
		{"injection", SQLite, "t; DROP TABLE users"},
		{"quoted", SQLite, `"t"`},
		{"empty", SQLite, ""},
		{"leading digit", SQLite, "1t"},
		{"unknown dialect", Dialect(9), "t"},
	}
	for _, tt := range tests {
		if _, err := New(nil, tt.dialect, tt.table); err == nil {
			t.Errorf("%s: New(%q) accepted", tt.name, tt.table)
		}
	}
}

func TestOnceRejectsBadKeys(t *testing.T) {
	s, _ := New(nil, SQLite, "t")
	for _, key := range []string{"", strings.Repeat("k", MaxKeyLen+1)} {
		called := false
		_, err := s.Once(context.Background(), key, func(context.Context) error { called = true; return nil })
		if err == nil || called {
			t.Errorf("key of length %d: err = %v, fn called = %v; want an error before touching the database", len(key), err, called)
		}
	}
}

func TestExecOutsideOnce(t *testing.T) {
	if _, err := Exec(context.Background(), "SELECT 1"); !errors.Is(err, ErrNoTx) {
		t.Fatalf("Exec outside Once = %v, want ErrNoTx", err)
	}
}
