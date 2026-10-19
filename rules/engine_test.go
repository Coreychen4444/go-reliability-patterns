package rules

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeStore counts loads and can hold each load until released.
type fakeStore struct {
	mu      sync.Mutex
	rules   RuleSet
	err     error
	started chan struct{} // if set, receives once per load
	release chan struct{} // if set, each load waits for it to close
	ctxErrs []error       // ctx.Err() seen by each load as it returns

	calls atomic.Int32
}

func (s *fakeStore) LoadRules(ctx context.Context, _ string) (RuleSet, error) {
	s.calls.Add(1)
	s.mu.Lock()
	rs, err, started, release := s.rules, s.err, s.started, s.release
	s.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
		}
	}
	s.mu.Lock()
	s.ctxErrs = append(s.ctxErrs, ctx.Err())
	s.mu.Unlock()
	if ctx.Err() != nil {
		return RuleSet{}, ctx.Err()
	}
	return rs, err
}

func (s *fakeStore) set(rs RuleSet, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules, s.err, s.release = rs, err, nil
}

var (
	denyXX = RuleSet{Deny: []DenyRule{{ID: "geo", Location: "XX"}}}
	fromXX = Request{Tenant: "t1", Account: "bob", Location: "XX"}
)

func TestFailClosed(t *testing.T) {
	boom := errors.New("connection refused")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name    string
		store   *fakeStore
		ctx     context.Context
		opts    []Option
		wantErr error
	}{
		{"store error", &fakeStore{err: boom}, context.Background(), nil, boom},
		{"rules fail to compile", &fakeStore{rules: RuleSet{Deny: []DenyRule{{ID: "empty"}}}}, context.Background(), nil, ErrInvalidRule},
		{"caller already cancelled", &fakeStore{rules: denyXX}, cancelled, nil, context.Canceled},
		{"store slower than load timeout", &fakeStore{release: make(chan struct{})}, context.Background(), []Option{WithLoadTimeout(20 * time.Millisecond)}, context.DeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEngine(tt.store, tt.opts...)
			// This request matches no rule, so only a failure can deny it.
			d := e.Check(tt.ctx, Request{Tenant: "t1", Account: "bob", Location: "SG"})
			if d.Allowed || d.Reason != RulesUnavailable || !errors.Is(d.Err, tt.wantErr) {
				t.Errorf("got %+v; want a RulesUnavailable denial wrapping %v", d, tt.wantErr)
			}
		})
	}
}

func TestErrorsAreNotCached(t *testing.T) {
	store := &fakeStore{err: errors.New("timeout")}
	e := NewEngine(store)
	if d := e.Check(context.Background(), fromXX); d.Reason != RulesUnavailable {
		t.Fatalf("got %+v, want RulesUnavailable", d)
	}
	store.set(denyXX, nil)
	if d := e.Check(context.Background(), fromXX); d.Reason != DenyRuleMatched {
		t.Fatalf("after the store recovered: got %+v, want DenyRuleMatched", d)
	}
}

func TestCaching(t *testing.T) {
	tests := []struct {
		name  string
		rules RuleSet
		want  Reason
	}{
		{"tenant with rules", denyXX, DenyRuleMatched},
		// Without a cached empty marker, every check for this tenant would
		// reach the store; singleflight only merges concurrent misses.
		{"tenant without rules", RuleSet{}, NoMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeStore{rules: tt.rules}
			e := NewEngine(store)
			for i := 0; i < 100; i++ {
				if d := e.Check(context.Background(), fromXX); d.Reason != tt.want {
					t.Fatalf("check %d: got %+v, want %v", i, d, tt.want)
				}
			}
			if n := store.calls.Load(); n != 1 {
				t.Errorf("store loaded %d times for 100 checks, want 1", n)
			}
		})
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestTTL(t *testing.T) {
	tests := []struct {
		name  string
		rules RuleSet
		// cumulative clock advance → expected total loads
		steps []struct {
			at    time.Duration
			loads int32
		}
	}{
		{"non-empty uses TTL", denyXX, []struct {
			at    time.Duration
			loads int32
		}{{0, 1}, {9 * time.Second, 1}, {11 * time.Second, 1}, {59 * time.Second, 1}, {61 * time.Second, 2}}},
		{"empty uses the shorter empty TTL", RuleSet{}, []struct {
			at    time.Duration
			loads int32
		}{{0, 1}, {9 * time.Second, 1}, {11 * time.Second, 2}, {19 * time.Second, 2}, {22 * time.Second, 3}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
			cache := NewMemoryCache()
			cache.now = clock.Now
			store := &fakeStore{rules: tt.rules}
			e := NewEngine(store, WithCache(cache), WithTTL(time.Minute), WithEmptyTTL(10*time.Second))
			var elapsed time.Duration
			for _, s := range tt.steps {
				clock.Advance(s.at - elapsed)
				elapsed = s.at
				e.Check(context.Background(), fromXX)
				if n := store.calls.Load(); n != s.loads {
					t.Errorf("at +%v: %d loads, want %d", s.at, n, s.loads)
				}
			}
		})
	}
}

func TestConcurrentMissesShareOneLoad(t *testing.T) {
	store := &fakeStore{rules: denyXX, started: make(chan struct{}, 64), release: make(chan struct{})}
	e := NewEngine(store)
	const n = 50
	decisions := make([]Decision, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decisions[i] = e.Check(context.Background(), fromXX)
		}()
	}
	<-store.started // the first load is in flight; the rest join it or hit the cache
	close(store.release)
	wg.Wait()
	if c := store.calls.Load(); c != 1 {
		t.Errorf("%d concurrent cold checks caused %d loads, want 1", n, c)
	}
	for i, d := range decisions {
		if d.Reason != DenyRuleMatched {
			t.Errorf("check %d: got %+v", i, d)
		}
	}
}

// The caller that starts a load may give up; the callers that joined it must
// still get the result.
func TestCancelledLeaderDoesNotFailWaiters(t *testing.T) {
	store := &fakeStore{rules: denyXX, started: make(chan struct{}, 4), release: make(chan struct{})}
	e := NewEngine(store)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leader := make(chan Decision)
	go func() { leader <- e.Check(leaderCtx, fromXX) }()
	<-store.started

	waiter := make(chan Decision)
	go func() { waiter <- e.Check(context.Background(), fromXX) }()

	cancelLeader()
	if d := <-leader; d.Reason != RulesUnavailable || !errors.Is(d.Err, context.Canceled) {
		t.Fatalf("leader: got %+v, want a cancelled RulesUnavailable", d)
	}
	close(store.release)
	if d := <-waiter; d.Reason != DenyRuleMatched {
		t.Fatalf("waiter: got %+v, want DenyRuleMatched", d)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.calls.Load() != 1 || store.ctxErrs[0] != nil {
		t.Fatalf("loads=%d, load ctx err=%v; want 1 load that was not cancelled", store.calls.Load(), store.ctxErrs[0])
	}
}

// A load that read the old rules must not put them back into the cache after
// Invalidate.
func TestInvalidateDuringLoad(t *testing.T) {
	release := make(chan struct{})
	store := &fakeStore{rules: denyXX, started: make(chan struct{}, 4), release: release}
	e := NewEngine(store)

	first := make(chan Decision)
	go func() { first <- e.Check(context.Background(), fromXX) }()
	<-store.started // the load has read denyXX and is blocked

	store.set(RuleSet{}, nil) // the admin removes the rule...
	if err := e.Invalidate(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	close(release) // ...and the old load finishes afterwards

	if d := <-first; d.Reason != DenyRuleMatched {
		t.Fatalf("in-flight check: got %+v, want the old rules' DenyRuleMatched", d)
	}
	if d := e.Check(context.Background(), fromXX); d.Reason != NoMatch {
		t.Fatalf("check after Invalidate: got %+v, want NoMatch from the new rules", d)
	}
	if n := store.calls.Load(); n != 2 {
		t.Fatalf("store loaded %d times, want 2", n)
	}
}

type brokenCache struct{}

func (brokenCache) Get(context.Context, string) (*Policy, bool, error) {
	return nil, false, errors.New("cache down")
}
func (brokenCache) Set(context.Context, string, *Policy, time.Duration) error {
	return errors.New("cache down")
}
func (brokenCache) Delete(context.Context, string) error { return errors.New("cache down") }

func TestBrokenCacheFallsBackToStore(t *testing.T) {
	store := &fakeStore{rules: denyXX}
	e := NewEngine(store, WithCache(brokenCache{}))
	for i := 0; i < 3; i++ {
		if d := e.Check(context.Background(), fromXX); d.Reason != DenyRuleMatched {
			t.Fatalf("got %+v, want DenyRuleMatched", d)
		}
	}
	if n := store.calls.Load(); n != 3 {
		t.Errorf("store loaded %d times, want 3 (no cache)", n)
	}
}

func TestConcurrentChecksAndInvalidations(t *testing.T) {
	store := &fakeStore{rules: denyXX}
	e := NewEngine(store)
	ctx := context.Background()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				tenant := fmt.Sprintf("t%d", i%4)
				if i%50 == 0 {
					_ = e.Invalidate(ctx, tenant)
				}
				req := fromXX
				req.Tenant = tenant
				if d := e.Check(ctx, req); d.Reason != DenyRuleMatched {
					t.Errorf("got %+v", d)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// BenchmarkCheckCached measures a check against a cached policy of 100 deny
// rules, none of which match, so every rule is evaluated.
func BenchmarkCheckCached(b *testing.B) {
	var rs RuleSet
	for i := 0; i < 100; i++ {
		rs.Deny = append(rs.Deny, DenyRule{ID: fmt.Sprintf("r%03d", i), Priority: i, Location: "XX", BankCard: fmt.Sprintf("4000%012d", i)})
	}
	e := NewEngine(StoreFunc(func(context.Context, string) (RuleSet, error) { return rs, nil }))
	req := Request{Tenant: "t1", Account: "bob", Location: "XX", BankCard: "5500 0000 0000 0004"}
	ctx := context.Background()
	b.Run("serial", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if d := e.Check(ctx, req); !d.Allowed {
				b.Fatal("unexpected denial")
			}
		}
	})
	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if d := e.Check(ctx, req); !d.Allowed {
					b.Fatal("unexpected denial")
				}
			}
		})
	})
}
