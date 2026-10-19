package idempotent

import (
	"regexp"
	"testing"
)

func TestKey(t *testing.T) {
	tests := []struct {
		name string
		a, b []string // namespace first
		same bool
	}{
		{"deterministic", []string{"invoice-paid", "inv-42"}, []string{"invoice-paid", "inv-42"}, true},
		{"namespace matters", []string{"invoice-paid", "inv-42"}, []string{"invoice-voided", "inv-42"}, false},
		{"order matters", []string{"transfer", "acct-1", "acct-2"}, []string{"transfer", "acct-2", "acct-1"}, false},
		{"no concatenation ambiguity", []string{"ns", "ab", "c"}, []string{"ns", "a", "bc"}, false},
		{"empty part counts", []string{"ns", "a", ""}, []string{"ns", "a"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ka, kb := Key(tt.a[0], tt.a[1:]...), Key(tt.b[0], tt.b[1:]...)
			if (ka == kb) != tt.same {
				t.Errorf("Key(%q) = %s, Key(%q) = %s; same = %v, want %v", tt.a, ka, tt.b, kb, ka == kb, tt.same)
			}
		})
	}
}

func TestKeyFormat(t *testing.T) {
	k := Key("invoice-paid", "inv-42")
	if !regexp.MustCompile(`^invoice-paid:[0-9a-f]{32}$`).MatchString(k) {
		t.Errorf("Key = %q, want namespace:32 hex characters", k)
	}
}
