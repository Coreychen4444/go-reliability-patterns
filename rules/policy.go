// Package rules is a per-tenant allow/deny engine for access checks such as
// login or withdrawal screening.
//
// A tenant's rules are evaluated in a fixed order:
//
//  1. If the rules cannot be loaded, the request is denied (fail closed).
//  2. Allowlist entries are checked by dimension: account, then nickname, then
//     IP. Each entry matches on a single dimension, and the first hit allows
//     the request regardless of any deny rule.
//  3. Deny rules are checked from the highest priority down. A rule names any
//     subset of account, nickname, IP (or prefix), IP location and bank card,
//     and matches only when all of them match (AND). The first match denies.
//  4. Otherwise the request is allowed.
//
// Compiled rule sets are cached per tenant behind the Cache interface.
// Concurrent cache misses for a tenant share one store load (singleflight),
// and empty rule sets are cached too, so a tenant without rules does not
// reach the store on every check.
package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// A Dimension is a request attribute that rules match on.
type Dimension int

const (
	Account Dimension = iota + 1
	Nickname
	IP
	Location
	BankCard
)

func (d Dimension) String() string {
	switch d {
	case Account:
		return "account"
	case Nickname:
		return "nickname"
	case IP:
		return "ip"
	case Location:
		return "location"
	case BankCard:
		return "bank_card"
	default:
		return fmt.Sprintf("Dimension(%d)", int(d))
	}
}

// A Request is the subject of a check. Empty fields, and an invalid IP, are
// missing signals; see WithStrictSignals for how deny rules treat them.
type Request struct {
	Tenant   string
	Account  string
	Nickname string
	IP       netip.Addr
	Location string // IP location, such as an ISO country code, resolved by the caller
	BankCard string
}

// An AllowEntry allows every request that matches it on one dimension:
// Account, Nickname or IP. For IP, Value is an address or a CIDR prefix.
type AllowEntry struct {
	ID        string
	Dimension Dimension
	Value     string
}

// A DenyRule denies requests that match all of its non-empty fields. IP is an
// address or a CIDR prefix. Rules with a higher Priority are checked first;
// ties are broken by ID so the result is deterministic.
type DenyRule struct {
	ID       string
	Priority int
	Account  string
	Nickname string
	IP       string
	Location string
	BankCard string
}

// A RuleSet is a tenant's rules as stored.
type RuleSet struct {
	Allow []AllowEntry
	Deny  []DenyRule
}

// A Reason explains a Decision.
type Reason int

const (
	NoMatch          Reason = iota // allowed: no rule matched
	Allowlisted                    // allowed by an allowlist entry
	DenyRuleMatched                // denied by a deny rule
	RulesUnavailable               // denied: the rules could not be loaded
)

func (r Reason) String() string {
	switch r {
	case NoMatch:
		return "no_match"
	case Allowlisted:
		return "allowlisted"
	case DenyRuleMatched:
		return "deny_rule"
	case RulesUnavailable:
		return "rules_unavailable"
	default:
		return fmt.Sprintf("Reason(%d)", int(r))
	}
}

// A Decision is the result of a check. There is no separate error return:
// a failure is a denial with Reason RulesUnavailable, so a caller cannot turn
// an unchecked error into an allow.
type Decision struct {
	Allowed   bool
	Reason    Reason
	RuleID    string    // the allowlist entry or deny rule that decided
	Dimension Dimension // for Allowlisted: the dimension that matched
	Err       error     // for RulesUnavailable
}

// A Policy is a compiled, immutable RuleSet. It is safe for concurrent use.
type Policy struct {
	allowAccount  map[string]string // account → entry ID
	allowNickname map[string]string // normalised nickname → entry ID
	allowIP       []prefixEntry
	deny          []denyRule // sorted by priority, highest first
}

type prefixEntry struct {
	prefix netip.Prefix
	id     string
}

type denyRule struct {
	id       string
	priority int
	account  string
	nickname string
	ip       netip.Prefix
	hasIP    bool
	location string
	card     string
}

// ErrInvalidRule is wrapped by every Compile error.
var ErrInvalidRule = errors.New("invalid rule")

// Compile validates rs and builds a Policy. Validate rules with Compile when
// they are written; the engine also compiles on load, and a rule set that
// fails to compile there denies every request for the tenant.
func Compile(rs RuleSet) (*Policy, error) {
	p := &Policy{
		allowAccount:  make(map[string]string),
		allowNickname: make(map[string]string),
	}
	for _, a := range rs.Allow {
		v := strings.TrimSpace(a.Value)
		if v == "" {
			return nil, fmt.Errorf("%w: allow entry %q has no value", ErrInvalidRule, a.ID)
		}
		switch a.Dimension {
		case Account:
			p.allowAccount[v] = a.ID
		case Nickname:
			p.allowNickname[normNickname(v)] = a.ID
		case IP:
			prefix, err := parsePrefix(v)
			if err != nil {
				return nil, fmt.Errorf("%w: allow entry %q: %v", ErrInvalidRule, a.ID, err)
			}
			p.allowIP = append(p.allowIP, prefixEntry{prefix, a.ID})
		default:
			return nil, fmt.Errorf("%w: allow entry %q: allowlists match on account, nickname or ip, not %v", ErrInvalidRule, a.ID, a.Dimension)
		}
	}
	for _, d := range rs.Deny {
		r := denyRule{
			id:       d.ID,
			priority: d.Priority,
			account:  strings.TrimSpace(d.Account),
			nickname: normNickname(d.Nickname),
			location: normLocation(d.Location),
			card:     normCard(d.BankCard),
		}
		if ip := strings.TrimSpace(d.IP); ip != "" {
			prefix, err := parsePrefix(ip)
			if err != nil {
				return nil, fmt.Errorf("%w: deny rule %q: %v", ErrInvalidRule, d.ID, err)
			}
			r.ip, r.hasIP = prefix, true
		}
		if strings.TrimSpace(d.BankCard) != "" && r.card == "" {
			return nil, fmt.Errorf("%w: deny rule %q: bank card %q has no digits", ErrInvalidRule, d.ID, d.BankCard)
		}
		if r.account == "" && r.nickname == "" && !r.hasIP && r.location == "" && r.card == "" {
			// A rule with no condition would deny every request.
			return nil, fmt.Errorf("%w: deny rule %q has no condition", ErrInvalidRule, d.ID)
		}
		p.deny = append(p.deny, r)
	}
	sort.SliceStable(p.deny, func(i, j int) bool {
		if p.deny[i].priority != p.deny[j].priority {
			return p.deny[i].priority > p.deny[j].priority
		}
		return p.deny[i].id < p.deny[j].id
	})
	return p, nil
}

// Empty reports whether the policy has no rules.
func (p *Policy) Empty() bool {
	return len(p.allowAccount) == 0 && len(p.allowNickname) == 0 && len(p.allowIP) == 0 && len(p.deny) == 0
}

// evaluate applies the policy to req. With strict set, a deny-rule condition
// on a missing signal counts as matched, so missing data denies rather than
// allows.
func (p *Policy) evaluate(req Request, strict bool) Decision {
	account := strings.TrimSpace(req.Account)
	nickname := normNickname(req.Nickname)
	ip := req.IP.Unmap() // so ::ffff:10.0.0.1 matches 10.0.0.0/8
	location := normLocation(req.Location)
	card := normCard(req.BankCard)

	if id, ok := p.allowAccount[account]; ok && account != "" {
		return Decision{Allowed: true, Reason: Allowlisted, RuleID: id, Dimension: Account}
	}
	if id, ok := p.allowNickname[nickname]; ok && nickname != "" {
		return Decision{Allowed: true, Reason: Allowlisted, RuleID: id, Dimension: Nickname}
	}
	if ip.IsValid() {
		for _, e := range p.allowIP {
			if e.prefix.Contains(ip) {
				return Decision{Allowed: true, Reason: Allowlisted, RuleID: e.id, Dimension: IP}
			}
		}
	}

	for i := range p.deny {
		r := &p.deny[i]
		if cond(r.account != "", account != "", account == r.account, strict) &&
			cond(r.nickname != "", nickname != "", nickname == r.nickname, strict) &&
			cond(r.hasIP, ip.IsValid(), r.ip.Contains(ip), strict) &&
			cond(r.location != "", location != "", location == r.location, strict) &&
			cond(r.card != "", card != "", card == r.card, strict) {
			return Decision{Allowed: false, Reason: DenyRuleMatched, RuleID: r.id}
		}
	}
	return Decision{Allowed: true, Reason: NoMatch}
}

// cond evaluates one condition of a deny rule. An unset condition matches
// anything; a set condition on a missing signal matches only in strict mode.
func cond(set, present, equal, strict bool) bool {
	switch {
	case !set:
		return true
	case !present:
		return strict
	default:
		return equal
	}
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func normNickname(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func normLocation(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

// normCard keeps only the digits, so "4111 1111-1111 1111" matches
// "4111111111111111". A production system would store and compare a keyed
// hash of the card number rather than the number itself.
func normCard(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if '0' <= s[i] && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
