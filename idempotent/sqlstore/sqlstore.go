// Package sqlstore is an idempotent.Store on database/sql. It works with
// SQLite, PostgreSQL and MySQL; the caller supplies the driver.
//
// Once runs in a transaction. It inserts the idempotency key with a
// conflict-ignoring insert; if no row was inserted the key was already
// processed and the transaction is rolled back. Otherwise it calls fn, and
// commits only if fn succeeds. fn can write its own rows in the same
// transaction (see Tx), so the effect and the key commit or roll back
// together.
//
// For an effect in another system (an HTTP call, another service's database)
// there is no shared transaction. Pass the idempotency key along as that
// system's request or transaction ID so it can de-duplicate on its side.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// A Dialect selects the SQL syntax.
type Dialect int

const (
	SQLite Dialect = iota
	Postgres
	MySQL
)

// MaxKeyLen is the longest key Once accepts, and the column width CreateTable
// uses. Longer keys are rejected rather than silently truncated by the
// database (which MySQL's INSERT IGNORE would do, merging distinct keys).
const MaxKeyLen = 128

// Store is an idempotent.Store backed by a SQL table.
type Store struct {
	db      *sql.DB
	dialect Dialect
	table   string
	insert  string
	purge   string
	now     func() time.Time
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// New returns a Store that records keys in table. The table name is
// interpolated into SQL, so it must be a plain identifier.
func New(db *sql.DB, d Dialect, table string) (*Store, error) {
	if !identifier.MatchString(table) {
		return nil, fmt.Errorf("sqlstore: invalid table name %q", table)
	}
	s := &Store{db: db, dialect: d, table: table, now: time.Now}
	switch d {
	case SQLite:
		s.insert = `INSERT INTO ` + table + ` (idempotency_key, processed_at_ms) VALUES (?, ?) ON CONFLICT (idempotency_key) DO NOTHING`
		s.purge = `DELETE FROM ` + table + ` WHERE processed_at_ms < ?`
	case Postgres:
		s.insert = `INSERT INTO ` + table + ` (idempotency_key, processed_at_ms) VALUES ($1, $2) ON CONFLICT (idempotency_key) DO NOTHING`
		s.purge = `DELETE FROM ` + table + ` WHERE processed_at_ms < $1`
	case MySQL:
		// INSERT IGNORE reports 0 affected rows for a duplicate however the
		// driver's CLIENT_FOUND_ROWS flag is set. The no-op
		// "ON DUPLICATE KEY UPDATE k = k" reports 1 when that flag is on,
		// which would look like a fresh insert. INSERT IGNORE's drawback,
		// turning errors such as truncation into warnings, is covered by the
		// MaxKeyLen check.
		s.insert = `INSERT IGNORE INTO ` + table + ` (idempotency_key, processed_at_ms) VALUES (?, ?)`
		s.purge = `DELETE FROM ` + table + ` WHERE processed_at_ms < ?`
	default:
		return nil, fmt.Errorf("sqlstore: unknown dialect %d", d)
	}
	return s, nil
}

// CreateTable creates the key table if it does not exist.
func (s *Store) CreateTable(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s (idempotency_key VARCHAR(%d) NOT NULL PRIMARY KEY, processed_at_ms BIGINT NOT NULL)`,
		s.table, MaxKeyLen))
	return err
}

type txKey struct{}

// Tx returns the transaction of the Once call that ctx was passed to, or nil.
// Handlers use it to write their effects atomically with the key.
func Tx(ctx context.Context) *sql.Tx {
	tx, _ := ctx.Value(txKey{}).(*sql.Tx)
	return tx
}

// Once implements idempotent.Store.
//
// Two transactions inserting the same key serialise on the primary key: the
// second blocks until the first commits (and then inserts nothing) or rolls
// back (and then inserts). So fn never runs twice concurrently for one key.
func (s *Store) Once(ctx context.Context, key string, fn func(context.Context) error) (duplicate bool, err error) {
	if key == "" || len(key) > MaxKeyLen {
		return false, fmt.Errorf("sqlstore: key length %d is outside 1..%d", len(key), MaxKeyLen)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	res, err := tx.ExecContext(ctx, s.insert, key, s.now().UnixMilli())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return true, nil
	}
	if err := fn(context.WithValue(ctx, txKey{}, tx)); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	committed = true
	return false, nil
}

// Purge deletes keys recorded before t. Keep keys for longer than the longest
// time a message can be redelivered (broker retention plus replay window), or
// a late duplicate will be processed again.
func (s *Store) Purge(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.purge, t.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ErrNoTx is returned by helpers that need the Once transaction but were
// called outside it.
var ErrNoTx = errors.New("sqlstore: no transaction in context; call from inside Once")

// Exec runs a statement in the Once transaction carried by ctx.
func Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	tx := Tx(ctx)
	if tx == nil {
		return nil, ErrNoTx
	}
	return tx.ExecContext(ctx, query, args...)
}
