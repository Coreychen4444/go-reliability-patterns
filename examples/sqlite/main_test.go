package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Coreychen4444/go-reliability-patterns/idempotent"
	"github.com/Coreychen4444/go-reliability-patterns/idempotent/sqlstore"
)

func newDB(t *testing.T) (*sql.DB, *sqlstore.Store) {
	t.Helper()
	db, err := open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := setup(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return db, store
}

func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func insertEntry(id string) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := sqlstore.Exec(ctx, `INSERT INTO ledger_entries (entry_id, account, amount_cents) VALUES (?, 'acct', 100)`, id)
		return err
	}
}

func TestOnce(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")
	tests := []struct {
		name        string
		steps       []func(context.Context) error
		wantDup     []bool
		wantErr     []error
		wantKeys    int
		wantEntries int
	}{
		{
			name:        "second call is a duplicate",
			steps:       []func(context.Context) error{insertEntry("e1"), insertEntry("e1")},
			wantDup:     []bool{false, true},
			wantErr:     []error{nil, nil},
			wantKeys:    1,
			wantEntries: 1,
		},
		{
			name: "failure rolls back the key and the effect",
			steps: []func(context.Context) error{
				func(ctx context.Context) error {
					if err := insertEntry("e1")(ctx); err != nil {
						return err
					}
					return boom // fails after writing
				},
				insertEntry("e1"),
			},
			wantDup:     []bool{false, false},
			wantErr:     []error{boom, nil},
			wantKeys:    1,
			wantEntries: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, store := newDB(t)
			for i, step := range tt.steps {
				dup, err := store.Once(ctx, "key-1", step)
				if dup != tt.wantDup[i] || !errors.Is(err, tt.wantErr[i]) {
					t.Fatalf("step %d: duplicate = %v, err = %v; want %v, %v", i, dup, err, tt.wantDup[i], tt.wantErr[i])
				}
			}
			if k, e := count(t, db, "processed_messages"), count(t, db, "ledger_entries"); k != tt.wantKeys || e != tt.wantEntries {
				t.Fatalf("%d keys and %d ledger entries; want %d and %d", k, e, tt.wantKeys, tt.wantEntries)
			}
		})
	}
}

func TestOnceConcurrentSameKey(t *testing.T) {
	db, store := newDB(t)
	var runs, dups atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dup, err := store.Once(context.Background(), "same-key", func(ctx context.Context) error {
				runs.Add(1)
				return insertEntry("e1")(ctx)
			})
			if err != nil {
				t.Error(err)
			}
			if dup {
				dups.Add(1)
			}
		}()
	}
	wg.Wait()
	if runs.Load() != 1 || dups.Load() != 19 || count(t, db, "ledger_entries") != 1 {
		t.Fatalf("runs = %d, duplicates = %d, entries = %d; want 1, 19, 1", runs.Load(), dups.Load(), count(t, db, "ledger_entries"))
	}
}

func TestPurgeForgetsOldKeys(t *testing.T) {
	ctx := context.Background()
	db, store := newDB(t)
	noop := func(context.Context) error { return nil }
	if _, err := store.Once(ctx, "k", noop); err != nil {
		t.Fatal(err)
	}
	if n, err := store.Purge(ctx, time.Now().Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("purging keys older than an hour removed %d (err %v), want 0", n, err)
	}
	if n, err := store.Purge(ctx, time.Now().Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("purging everything removed %d (err %v), want 1", n, err)
	}
	// After the retention window a redelivery is processed again: retention
	// must outlast the longest possible redelivery delay.
	if dup, err := store.Once(ctx, "k", noop); dup || err != nil {
		t.Fatalf("after purge: duplicate = %v, err = %v; want a fresh run", dup, err)
	}
	if count(t, db, "processed_messages") != 1 {
		t.Fatal("key not recorded again")
	}
}

func TestConsumerEndToEnd(t *testing.T) {
	ctx := context.Background()
	db, store := newDB(t)
	var deadLettered []string
	var mu sync.Mutex
	dlq := idempotent.DeadLetterFunc(func(_ context.Context, msg idempotent.Message, _ int, _ error) error {
		mu.Lock()
		deadLettered = append(deadLettered, string(msg.Value))
		mu.Unlock()
		return nil
	})
	c := idempotent.NewConsumer(store, invoiceKey, credit, idempotent.WithLanes(4), idempotent.WithDeadLetter(dlq))

	var batch []idempotent.Message
	want := map[string]int64{}
	for i := 0; i < 40; i++ {
		acct := fmt.Sprintf("acct-%d", i%6)
		cents := int64(100 * (i + 1))
		batch = append(batch, event(fmt.Sprintf("inv-%d", i), acct, cents))
		want[acct] += cents
	}
	in := make(chan idempotent.Message, 3*len(batch)+1)
	for round := 0; round < 3; round++ {
		for _, m := range batch {
			in <- m
		}
	}
	in <- idempotent.Message{Key: "acct-0", Value: []byte(`not json`)}
	close(in)

	if err := c.Run(ctx, in, func(m idempotent.Message, err error) {
		if err != nil {
			t.Errorf("%s: %v", m.Value, err)
		}
	}); err != nil {
		t.Fatal(err)
	}

	got, err := balances(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("balances %v, want %v", got, want)
	}
	if s := c.Stats(); s.Processed != 40 || s.Duplicates != 80 || s.DeadLettered != 1 {
		t.Fatalf("stats %+v; want 40 processed, 80 duplicates, 1 dead-lettered", s)
	}
	if len(deadLettered) != 1 || deadLettered[0] != "not json" {
		t.Fatalf("dead letters %q", deadLettered)
	}
}
