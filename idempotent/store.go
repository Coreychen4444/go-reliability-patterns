package idempotent

import (
	"context"
	"fmt"
	"sync"
)

// A Store records processed idempotency keys.
type Store interface {
	// Once calls fn unless key has already been recorded, and records key
	// only if fn returns nil. duplicate reports that key was already recorded
	// and fn was not called.
	//
	// Recording the key and fn's own writes must succeed or fail together
	// (one database transaction). Otherwise a crash between the two either
	// loses the effect (key recorded first) or applies it twice (key recorded
	// last). Concurrent calls with the same key must not both run fn.
	Once(ctx context.Context, key string, fn func(ctx context.Context) error) (duplicate bool, err error)
}

// MemoryStore is an in-process Store, for tests and for effects that live in
// the same process. It keeps every key forever; a database store would delete
// keys older than the longest possible redelivery delay.
type MemoryStore struct {
	mu       sync.Mutex
	done     map[string]struct{}
	inflight map[string]chan struct{}
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{done: make(map[string]struct{}), inflight: make(map[string]chan struct{})}
}

// Once implements Store. A second caller with the same key waits for the
// first to finish, then either skips (the first succeeded) or runs fn itself
// (the first failed).
func (s *MemoryStore) Once(ctx context.Context, key string, fn func(context.Context) error) (bool, error) {
	for {
		s.mu.Lock()
		if _, ok := s.done[key]; ok {
			s.mu.Unlock()
			return true, nil
		}
		wait, busy := s.inflight[key]
		if !busy {
			ch := make(chan struct{})
			s.inflight[key] = ch
			s.mu.Unlock()
			return false, s.run(ctx, key, ch, fn)
		}
		s.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}

func (s *MemoryStore) run(ctx context.Context, key string, ch chan struct{}, fn func(context.Context) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("idempotent: handler panicked: %v", r)
		}
		s.mu.Lock()
		if err == nil {
			s.done[key] = struct{}{}
		}
		delete(s.inflight, key)
		close(ch)
		s.mu.Unlock()
	}()
	return fn(ctx)
}

// Len returns the number of recorded keys.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.done)
}
