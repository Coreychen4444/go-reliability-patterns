package idempotent_test

import (
	"context"
	"fmt"

	"github.com/Coreychen4444/go-reliability-patterns/idempotent"
)

func ExampleConsumer_Process() {
	balance := 0
	credit := func(_ context.Context, msg idempotent.Message) error {
		balance += 100
		return nil
	}
	key := func(msg idempotent.Message) (string, error) {
		return idempotent.Key("invoice-paid", msg.Headers["invoice-id"]), nil
	}
	c := idempotent.NewConsumer(idempotent.NewMemoryStore(), key, credit)

	msg := idempotent.Message{Key: "acct-1", Headers: map[string]string{"invoice-id": "inv-42"}}
	for i := 0; i < 3; i++ { // the broker delivers the same message three times
		if err := c.Process(context.Background(), msg); err != nil {
			fmt.Println(err)
		}
	}
	fmt.Println("balance:", balance)
	fmt.Printf("%+v\n", c.Stats())
	// Output:
	// balance: 100
	// {Processed:1 Duplicates:2 Retries:0 DeadLettered:0}
}
