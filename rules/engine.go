package rules

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// A Store loads a tenant's rules from the source of truth, such as a database.
type Store interface {
	LoadRules(ctx context.Context, tenant string) (RuleSet, error)
}

// StoreFunc adapts a function to the Store interface.
type StoreFunc func(ctx context.Context, tenant string) (RuleSet, error)

// LoadRules calls f.
func (f StoreFunc) LoadRules(ctx context.Context, tenant string) (RuleSet, error) {
	return f(ctx, tenant)
}

// A Cache holds compiled policies per tenant. Get must distinguish a cached
// empty policy (ok is true) from a miss (ok is false); that distinction is
// what lets the engine cache tenants that have no rules. A Redis-backed cache
// would store the RuleSet and recompile, or keep a marker for "empty".
//
// The engine treats a Get error as a miss and ignores Set errors: the cache is
// an optimisation, and the store stays the source of truth.
type Cache interface {
	Get(ctx context.Context, tenant string) (p *Policy, ok bool, err error)
	Set(ctx context.Context, tenant string, p *Policy, ttl time.Duration) error
	Delete(ctx context.Context, tenant string) error
}

// An Engine checks requests against per-tenant rules. It is safe for
// concurrent use.
type Engine struct {
	store       Store
	cache       Cache
	ttl         time.Duration
	emptyTTL    time.Duration
	loadTimeout time.Duration
	strict      bool

	group singleflight.Group

	mu  sync.Mutex
	gen map[string]uint64 // bumped by Invalidate
}

// An Option configures an Engine.
type Option func(*Engine)

// WithCache sets the policy cache. The default is a MemoryCache.
func WithCache(c Cache) Option { return func(e *Engine) { e.cache = c } }

// WithTTL sets how long a policy is cached. The default is one minute.
func WithTTL(d time.Duration) Option { return func(e *Engine) { e.ttl = d } }

// WithEmptyTTL sets how long an empty policy is cached. It is shorter than
// the normal TTL by default (ten seconds) so a tenant's first rule takes
// effect quickly even if an invalidation is lost.
func WithEmptyTTL(d time.Duration) Option { return func(e *Engine) { e.emptyTTL = d } }

// WithLoadTimeout bounds a store load. The default is two seconds.
func WithLoadTimeout(d time.Duration) Option { return func(e *Engine) { e.loadTimeout = d } }

// WithStrictSignals makes a deny-rule condition on a missing request field
// (no location, no IP, ...) count as matched. Without it a missing signal
// never matches, so a rule such as "deny location XX" lets a request with an
// unknown location through.
func WithStrictSignals() Option { return func(e *Engine) { e.strict = true } }

// NewEngine returns an Engine that loads rules from store.
func NewEngine(store Store, opts ...Option) *Engine {
	e := &Engine{
		store:       store,
		ttl:         time.Minute,
		emptyTTL:    10 * time.Second,
		loadTimeout: 2 * time.Second,
		gen:         make(map[string]uint64),
	}
	for _, o := range opts {
		o(e)
	}
	if e.cache == nil {
		e.cache = NewMemoryCache()
	}
	return e
}

// Check decides whether req is allowed. It denies when the tenant's rules
// cannot be loaded or compiled, or when ctx ends before they are available.
func (e *Engine) Check(ctx context.Context, req Request) Decision {
	p, err := e.policy(ctx, req.Tenant)
	if err != nil {
		return Decision{Allowed: false, Reason: RulesUnavailable, Err: err}
	}
	return p.evaluate(req, e.strict)
}

// Invalidate drops the tenant's cached policy. Call it after changing the
// tenant's rules in the store. A load that started before the call cannot put
// its (possibly stale) result back into the cache.
func (e *Engine) Invalidate(ctx context.Context, tenant string) error {
	e.mu.Lock()
	e.gen[tenant]++
	e.mu.Unlock()
	// New callers start a fresh load instead of joining one that may have
	// read the old rules.
	e.group.Forget(tenant)
	return e.cache.Delete(ctx, tenant)
}

func (e *Engine) generation(tenant string) uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gen[tenant]
}

func (e *Engine) policy(ctx context.Context, tenant string) (*Policy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p, ok, err := e.cache.Get(ctx, tenant); err == nil && ok {
		return p, nil
	}
	ch := e.group.DoChan(tenant, func() (any, error) {
		return e.load(ctx, tenant)
	})
	select {
	case <-ctx.Done():
		// The load carries on for the other waiters and still fills the cache.
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*Policy), nil
	}
}

// load runs once per flight. Its context is detached from the caller that
// happened to start it: every waiter shares the result, so one caller
// cancelling must not fail the rest.
func (e *Engine) load(ctx context.Context, tenant string) (*Policy, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.loadTimeout)
	defer cancel()

	// A flight that finished between our miss and this one may have filled
	// the cache already.
	if p, ok, err := e.cache.Get(ctx, tenant); err == nil && ok {
		return p, nil
	}

	gen := e.generation(tenant)
	rs, err := e.store.LoadRules(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("rules: load tenant %q: %w", tenant, err)
	}
	p, err := Compile(rs)
	if err != nil {
		return nil, fmt.Errorf("rules: tenant %q: %w", tenant, err)
	}

	ttl := e.ttl
	if p.Empty() {
		ttl = e.emptyTTL
	}
	_ = e.cache.Set(ctx, tenant, p, ttl)
	// If Invalidate ran at any point since the load began, what was just
	// cached may predate the change. Checking after the Set (rather than
	// before) closes the window where Invalidate's Delete lands between the
	// check and the Set.
	if e.generation(tenant) != gen {
		_ = e.cache.Delete(ctx, tenant)
	}
	return p, nil
}

// MemoryCache is an in-process Cache with per-entry expiry. Expired entries
// are replaced on the next Set; the map holds at most one entry per tenant.
type MemoryCache struct {
	mu  sync.RWMutex
	m   map[string]memEntry
	now func() time.Time
}

type memEntry struct {
	p       *Policy
	expires time.Time
}

// NewMemoryCache returns an empty MemoryCache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{m: make(map[string]memEntry), now: time.Now}
}

// Get returns the tenant's policy if it is cached and not expired.
func (c *MemoryCache) Get(_ context.Context, tenant string) (*Policy, bool, error) {
	c.mu.RLock()
	e, ok := c.m[tenant]
	c.mu.RUnlock()
	if !ok || !c.now().Before(e.expires) {
		return nil, false, nil
	}
	return e.p, true, nil
}

// Set caches p for ttl.
func (c *MemoryCache) Set(_ context.Context, tenant string, p *Policy, ttl time.Duration) error {
	c.mu.Lock()
	c.m[tenant] = memEntry{p: p, expires: c.now().Add(ttl)}
	c.mu.Unlock()
	return nil
}

// Delete removes the tenant's policy.
func (c *MemoryCache) Delete(_ context.Context, tenant string) error {
	c.mu.Lock()
	delete(c.m, tenant)
	c.mu.Unlock()
	return nil
}
