// Command sqlite runs the idempotent consumer against SQLite. It delivers a
// batch of "invoice paid" events three times, the way a broker might after
// consumer restarts, plus one malformed event, and shows that every invoice
// is credited exactly once.
//
// It is a separate module so the SQLite driver and its dependencies stay out
// of the main module's go.mod.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Coreychen4444/go-reliability-patterns/idempotent"
	"github.com/Coreychen4444/go-reliability-patterns/idempotent/sqlstore"
	_ "modernc.org/sqlite"
)

type invoicePaid struct {
	InvoiceID   string `json:"invoice_id"`
	Account     string `json:"account"`
	AmountCents int64  `json:"amount_cents"`
}

// open opens a SQLite database. BEGIN IMMEDIATE takes the write lock up
// front, so two transactions inserting the same key queue on busy_timeout
// instead of failing on a lock upgrade.
func open(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate")
}

func setup(ctx context.Context, db *sql.DB) (*sqlstore.Store, error) {
	store, err := sqlstore.New(db, sqlstore.SQLite, "processed_messages")
	if err != nil {
		return nil, err
	}
	if err := store.CreateTable(ctx); err != nil {
		return nil, err
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS ledger_entries (
		entry_id     TEXT PRIMARY KEY,
		account      TEXT NOT NULL,
		amount_cents INTEGER NOT NULL)`)
	return store, err
}

func decode(msg idempotent.Message) (invoicePaid, error) {
	var e invoicePaid
	if err := json.Unmarshal(msg.Value, &e); err != nil {
		return e, err
	}
	if e.InvoiceID == "" {
		return e, errors.New("missing invoice_id")
	}
	return e, nil
}

// invoiceKey derives the idempotency key from the invoice ID: the business
// identity of the payment, not the delivery.
func invoiceKey(msg idempotent.Message) (string, error) {
	e, err := decode(msg)
	if err != nil {
		return "", err
	}
	return idempotent.Key("invoice-paid", e.InvoiceID), nil
}

// credit writes the ledger entry inside the store's transaction, so the entry
// and the processed key commit together. The entry ID is the idempotency key,
// which gives the ledger its own unique-key guard as well.
func credit(ctx context.Context, msg idempotent.Message) error {
	e, err := decode(msg)
	if err != nil {
		return idempotent.Permanent(err)
	}
	_, err = sqlstore.Exec(ctx,
		`INSERT INTO ledger_entries (entry_id, account, amount_cents) VALUES (?, ?, ?)`,
		idempotent.Key("invoice-paid", e.InvoiceID), e.Account, e.AmountCents)
	return err
}

func balances(ctx context.Context, db *sql.DB) (map[string]int64, error) {
	rows, err := db.QueryContext(ctx, `SELECT account, SUM(amount_cents) FROM ledger_entries GROUP BY account ORDER BY account`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var acct string
		var sum int64
		if err := rows.Scan(&acct, &sum); err != nil {
			return nil, err
		}
		out[acct] = sum
	}
	return out, rows.Err()
}

func event(invoice, account string, cents int64) idempotent.Message {
	v, _ := json.Marshal(invoicePaid{InvoiceID: invoice, Account: account, AmountCents: cents})
	return idempotent.Message{Topic: "invoice.paid", Key: account, Value: v}
}

func run(ctx context.Context, dbPath string) error {
	db, err := open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	store, err := setup(ctx, db)
	if err != nil {
		return err
	}

	dlq := idempotent.DeadLetterFunc(func(_ context.Context, msg idempotent.Message, attempts int, cause error) error {
		fmt.Printf("dead-lettered after %d attempt(s): %s: %v\n", attempts, msg.Value, cause)
		return nil
	})
	c := idempotent.NewConsumer(store, invoiceKey, credit, idempotent.WithLanes(4), idempotent.WithDeadLetter(dlq))

	batch := []idempotent.Message{
		event("inv-1001", "acct-a", 1250),
		event("inv-1002", "acct-b", 990),
		event("inv-1003", "acct-a", 4000),
		event("inv-1004", "acct-c", 15000),
		event("inv-1005", "acct-b", 10),
	}
	in := make(chan idempotent.Message, 3*len(batch)+1)
	for round := 0; round < 3; round++ {
		for _, m := range batch {
			in <- m
		}
	}
	in <- idempotent.Message{Topic: "invoice.paid", Key: "acct-a", Value: []byte(`{"invoice_id":`)}
	close(in)

	if err := c.Run(ctx, in, nil); err != nil {
		return err
	}
	b, err := balances(ctx, db)
	if err != nil {
		return err
	}
	fmt.Printf("balances (cents): %v\n", b)
	fmt.Printf("stats: %+v\n", c.Stats())
	return nil
}

func main() {
	dir, err := os.MkdirTemp("", "idempotent-demo-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := run(context.Background(), filepath.Join(dir, "demo.db")); err != nil {
		log.Fatal(err)
	}
}
