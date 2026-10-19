package rules_test

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/Coreychen4444/go-reliability-patterns/rules"
)

func ExampleEngine_Check() {
	store := rules.StoreFunc(func(_ context.Context, tenant string) (rules.RuleSet, error) {
		return rules.RuleSet{
			Allow: []rules.AllowEntry{{ID: "office", Dimension: rules.IP, Value: "10.0.0.0/8"}},
			Deny: []rules.DenyRule{
				{ID: "card-from-xx", Priority: 10, Location: "XX", BankCard: "4111 1111 1111 1111"},
			},
		}, nil
	})
	engine := rules.NewEngine(store)
	ctx := context.Background()

	for _, req := range []rules.Request{
		{Tenant: "t1", Account: "bob", Location: "XX", BankCard: "4111-1111-1111-1111"},
		{Tenant: "t1", Account: "bob", Location: "XX", BankCard: "5500 0000 0000 0004"},
		{Tenant: "t1", Account: "ops", Location: "XX", BankCard: "4111111111111111", IP: netip.MustParseAddr("10.1.2.3")},
	} {
		d := engine.Check(ctx, req)
		fmt.Printf("allowed=%v reason=%v rule=%q\n", d.Allowed, d.Reason, d.RuleID)
	}
	// Output:
	// allowed=false reason=deny_rule rule="card-from-xx"
	// allowed=true reason=no_match rule=""
	// allowed=true reason=allowlisted rule="office"
}
