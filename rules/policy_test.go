package rules

import (
	"errors"
	"net/netip"
	"testing"
)

var testRules = RuleSet{
	Allow: []AllowEntry{
		{ID: "allow-account", Dimension: Account, Value: "acct-trusted"},
		{ID: "allow-nickname", Dimension: Nickname, Value: "Alice"},
		{ID: "allow-office", Dimension: IP, Value: "10.0.0.0/8"},
	},
	Deny: []DenyRule{
		{ID: "deny-location", Priority: 10, Location: "xx"},
		{ID: "deny-card-in-yy", Priority: 20, Location: "YY", BankCard: "4111 1111 1111 1111"},
		{ID: "deny-trusted", Priority: 5, Account: "acct-trusted"}, // never fires: acct-trusted is allowlisted
		{ID: "deny-host", Priority: 30, IP: "203.0.113.7"},
		{ID: "deny-net-a", Priority: 1, IP: "198.51.100.0/24"},
		{ID: "deny-net-b", Priority: 1, IP: "198.51.100.0/25"},
		{ID: "deny-pair", Priority: 15, Account: "mallory", Nickname: "M"},
	},
}

func TestEvaluate(t *testing.T) {
	p, err := Compile(testRules)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr
	tests := []struct {
		name   string
		req    Request
		want   Reason
		ruleID string
		dim    Dimension
	}{
		{"nothing matches", Request{Account: "bob", Location: "SG"}, NoMatch, "", 0},
		{"allowlist beats deny rule", Request{Account: "acct-trusted", Location: "XX"}, Allowlisted, "allow-account", Account},
		{"account before nickname and ip", Request{Account: "acct-trusted", Nickname: "alice", IP: ip("10.1.2.3")}, Allowlisted, "allow-account", Account},
		{"nickname before ip", Request{Nickname: "alice", IP: ip("10.1.2.3")}, Allowlisted, "allow-nickname", Nickname},
		{"nickname ignores case and spaces", Request{Nickname: "  ALICE "}, Allowlisted, "allow-nickname", Nickname},
		{"ip allowlist prefix", Request{IP: ip("10.200.0.1"), Location: "XX"}, Allowlisted, "allow-office", IP},
		{"ipv4-mapped ipv6 address", Request{IP: ip("::ffff:10.0.0.1"), Location: "XX"}, Allowlisted, "allow-office", IP},
		{"single-condition deny", Request{Location: "xx"}, DenyRuleMatched, "deny-location", 0},
		{"AND: second condition missing", Request{Location: "YY"}, NoMatch, "", 0},
		{"AND: second condition differs", Request{Location: "YY", BankCard: "5500 0000 0000 0004"}, NoMatch, "", 0},
		{"AND: all match, card normalised", Request{Location: "yy", BankCard: "4111-1111-1111-1111"}, DenyRuleMatched, "deny-card-in-yy", 0},
		{"AND: one of two fields", Request{Account: "mallory"}, NoMatch, "", 0},
		{"AND: both fields", Request{Account: "mallory", Nickname: "m"}, DenyRuleMatched, "deny-pair", 0},
		{"single address", Request{IP: ip("203.0.113.7")}, DenyRuleMatched, "deny-host", 0},
		{"highest priority reported", Request{IP: ip("203.0.113.7"), Location: "XX"}, DenyRuleMatched, "deny-host", 0},
		{"priority tie broken by id", Request{IP: ip("198.51.100.9")}, DenyRuleMatched, "deny-net-a", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := p.evaluate(tt.req, false)
			wantAllowed := tt.want == NoMatch || tt.want == Allowlisted
			if d.Allowed != wantAllowed || d.Reason != tt.want || d.RuleID != tt.ruleID || d.Dimension != tt.dim {
				t.Errorf("got %+v; want allowed=%v reason=%v rule=%q dimension=%v", d, wantAllowed, tt.want, tt.ruleID, tt.dim)
			}
		})
	}
}

func TestMissingSignals(t *testing.T) {
	p, err := Compile(RuleSet{Deny: []DenyRule{
		{ID: "geo", Location: "XX"},
		{ID: "card-from-yy", Location: "YY", BankCard: "4111111111111111"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		req     Request
		strict  bool
		allowed bool
		ruleID  string
	}{
		{"unknown location is allowed by default", Request{Account: "bob"}, false, true, ""},
		{"unknown location is denied when strict", Request{Account: "bob"}, true, false, "card-from-yy"},
		{"missing card with matching location, default", Request{Location: "YY"}, false, true, ""},
		{"missing card with matching location, strict", Request{Location: "YY"}, true, false, "card-from-yy"},
		{"present signals that differ, strict", Request{Location: "SG", BankCard: "5500000000000004"}, true, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := p.evaluate(tt.req, tt.strict)
			if d.Allowed != tt.allowed || d.RuleID != tt.ruleID {
				t.Errorf("got %+v; want allowed=%v rule=%q", d, tt.allowed, tt.ruleID)
			}
		})
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name string
		rs   RuleSet
	}{
		{"allow entry without value", RuleSet{Allow: []AllowEntry{{ID: "a", Dimension: Account, Value: " "}}}},
		{"allow entry on location", RuleSet{Allow: []AllowEntry{{ID: "a", Dimension: Location, Value: "SG"}}}},
		{"allow entry with bad ip", RuleSet{Allow: []AllowEntry{{ID: "a", Dimension: IP, Value: "10.0.0.300"}}}},
		{"deny rule without condition", RuleSet{Deny: []DenyRule{{ID: "d", Priority: 1}}}},
		{"deny rule with bad prefix", RuleSet{Deny: []DenyRule{{ID: "d", IP: "10.0.0.0/33"}}}},
		{"deny rule with card but no digits", RuleSet{Deny: []DenyRule{{ID: "d", BankCard: "n/a"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Compile(tt.rs); !errors.Is(err, ErrInvalidRule) {
				t.Errorf("Compile error = %v, want ErrInvalidRule", err)
			}
		})
	}
}

func TestParsePrefix(t *testing.T) {
	tests := []struct{ in, want string }{
		{"203.0.113.7", "203.0.113.7/32"},
		{"10.1.2.3/8", "10.0.0.0/8"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"::ffff:10.0.0.1", "10.0.0.1/32"},
		{"::ffff:10.0.0.0/104", "10.0.0.0/8"},
	}
	for _, tt := range tests {
		got, err := parsePrefix(tt.in)
		if err != nil || got.String() != tt.want {
			t.Errorf("parsePrefix(%q) = %v, %v; want %s", tt.in, got, err, tt.want)
		}
	}
}
