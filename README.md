# go-reliability-patterns

Three backend reliability patterns in Go, each with table-driven tests, a
race-detector run, benchmarks and (for the redactor) fuzzing. Each package is
a from-scratch re-implementation of a pattern I worked on in production Go
services, written to show the design, its failure modes and its trade-offs.
No employer code, names or data are used.

| Package | Pattern | What to look at |
|---|---|---|
| [`redact`](redact) | Log redaction as an `io.Writer` decorator | Allocation-free keyword fast path, merged regexp, JSON-aware walker, fuzzed invariants |
| [`rules`](rules) | Per-tenant allow/deny engine | Fail-closed decisions, singleflight cache fill, cached empty results, invalidation race |
| [`idempotent`](idempotent) | At-least-once consumer with idempotent effects | Deterministic keys, key + effect in one transaction, retry/back-off/dead-letter, per-key ordering |

Go 1.22+, standard library first. The only dependency of the main module is
`golang.org/x/sync` (singleflight). The SQLite example lives in its own module
([`examples/sqlite`](examples/sqlite)) so its driver stays out of the main
`go.mod`.

```bash
make lint      # gofmt + go vet (both modules)
make test      # unit tests, plus SQLite integration tests
make race      # the same under -race
make bench     # benchmarks
make fuzz      # FuzzRedact for 60s (FUZZTIME=5m for longer)
make example   # run the SQLite consumer demo
```

---

## redact: masking secrets in logs

`redact.NewWriter(w, nil)` wraps any `io.Writer`. Put it under a `log/slog`,
zap or zerolog handler and secrets are masked before a log line leaves the
process:

```go
log := slog.New(slog.NewJSONHandler(redact.NewWriter(os.Stdout, nil), nil))
log.Info("login failed", "user", "bob", "password", "hunter2", "phone", "+65 9123 4567")
// {"time":"...","level":"INFO","msg":"login failed","user":"bob","password":"[REDACTED]","phone":"+65 9*** *567"}
```

It masks:

- values of secret keys: `password`, `token`, `secret`, `api_key`, `authorization` and others, in `key=value`, `key: value`, quoted values, JSON fields and JSON embedded in strings;
- `Authorization` headers and bare `Bearer` tokens, keeping the scheme (`Bearer [REDACTED]`);
- passwords in URLs (`postgres://app:[REDACTED]@db/main`);
- sensitive query parameters (`?access_token=[REDACTED]&page=2`);
- phone numbers under a phone key or written with a `+`, keeping a prefix and suffix visible (`+65 9*** *567`). At least four digits are always masked.

### How it works

```
line ──► fast path: lower-case into a stack buffer, look for trigger keywords
           │ none (most lines) ──► written through unchanged, 0 allocations
           ▼ some
         valid JSON? ──yes──► walker: mask values by key; free-text rules on other string values
           │ no
           ▼
         one merged regexp (5 rules as one alternation) ──► rewrite matched groups
```

- **Fast path.** Every rule declares the literals it cannot match without, such as its key names, `bearer`, `://` and `@` for URL credentials, or a `+` followed by eight or more digits for phones. One pass checks all keywords at once: a bitmap of each keyword's first two bytes skips almost every position. Lines up to 1 KiB are lower-cased into a stack buffer, so a clean line costs no allocation; a test asserts this with `testing.AllocsPerRun`.
- **Case folding.** Go's `(?i)` uses Unicode simple folding: `ſ` (U+017F) matches `s`, and the Kelvin sign (U+212A) matches `k`. The fast path folds those two runes as well; otherwise `paſſword=x` would skip the fast path but match the regexp.
- **JSON walker.** In a valid JSON document, a string followed by `:` is a key and every other string is a value. That is enough to mask values by key without a full parser. A secret key's value (string, number, object or array) becomes `"[REDACTED]"`. Phone numbers become strings with masked digits. `null`, booleans and `""` are left as they are. Only whole value tokens are replaced, and only with JSON strings, so the output stays valid JSON.
- **Free text.** The five rules are compiled into one case-insensitive alternation. Each rule records which of its capture groups to rewrite, so one pass gives a single precedence order: the leftmost match wins, then rule order. Value character classes exclude `\` and `"`, so a replacement never splits a JSON escape sequence inside a string.

### Fuzzed properties

`FuzzRedact` checks three invariants on arbitrary input:

1. **The fast path never changes the result.** Skipping a line must give the same output as running every rule on it, so no trigger can hide a secret the regexp would catch.
2. **Redaction is idempotent.** Logs that pass through two redactors (the app, then a shipper) are not mangled further.
3. **Valid single-line JSON stays valid JSON.**

The seed corpus found an idempotence bug on its first run: `Authorization: Bearer [REDACTED]` was re-redacted to `Authorization: [REDACTED] [REDACTED]`. The key-value rule now consumes an already-masked value without rewriting it.

### Failure modes and limits

| Case | Behaviour | Why / mitigation |
|---|---|---|
| Secret split across two `Write` calls | Missed | Each call is redacted on its own. slog, zap and zerolog write one record per call. |
| Unquoted value containing spaces or `,;&` | Only the first part is masked | `password=a b` cannot be told apart from `password=a` followed by more text. Quote it, or log it as a structured field. |
| Bare number with no `+` and no phone key | Not masked | `91234567` looks the same as an order ID or a timestamp. Precision was chosen over recall here. |
| JSON key written with escapes (`"password"`) | Missed | Keys are matched on their raw bytes. |
| Phone key holding an object (`"phone":{"number":...}`) | Nested keys are checked one by one | `number` is not a phone key. Add it with `WithPhoneKeys`. |
| Keyword in prose: `refresh token: expired` | Over-redacted to `token: [REDACTED]` | Over-redaction is the chosen failure direction for a redactor. |
| Many lines containing a keyword | Slow path at ~50 µs per line | See the benchmarks. Narrow the key list, or see the next steps below. |

### Benchmarks

Apple M2, darwin/arm64, Go 1.22.2; median of 3 runs (`make bench`).

| Line | fast path (shipped) | merged regexp only | one regexp per rule |
|---|---:|---:|---:|
| clean JSON (275 B) | **837 ns** · 0 allocs | 89.4 µs | 83.7 µs |
| clean text (162 B) | **445 ns** · 0 allocs | 53.3 µs | 49.1 µs |
| JSON with a password and phone (222 B) | **3.0 µs** · 0 allocs | 62.4 µs | 67.4 µs |
| text with a token and bearer (213 B) | 52.5 µs · 8 allocs | 53.2 µs | 54.6 µs |

Behind `slog.NewJSONHandler`, a clean record costs **1.08 µs** with the
redacting writer vs 0.58 µs without, at 0 allocations both ways.

What the numbers say:

- **The fast path is the optimisation.** Clean lines are 100–120× cheaper than running the regexp. A JSON line with secrets is about 20× cheaper because the walker runs the regexp only on string values that trigger.
- **Merging regexps does not pay off in Go.** Go's `regexp` has no DFA. It runs a bounded backtracker (programs up to 500 instructions) or a Pike VM, and both cost roughly *program size × input length*. The merged program is 357 instructions; the five rules compiled separately total about the same. So one pass over a big program costs the same as five passes over small ones. In RE2/C++ or Rust's `regex`, a lazy DFA makes the merged scan close to linear in the input regardless of rule count. In Go, what matters is the fast path and keeping the program small. Writing the phone patterns with `+` and counting digits in code, instead of `{7,14}`, removed about 170 instructions.
- **The first version of the fast path did not work for timezone offsets.** It treated any `+` followed by a digit as a possible phone number, so every slog line with a `+08:00` timestamp took the slow path (16 µs per record). The trigger now requires eight digits after the `+`.

---

## rules: fail-closed allow/deny engine

```go
engine := rules.NewEngine(store) // store loads a tenant's RuleSet, e.g. from SQL
d := engine.Check(ctx, rules.Request{Tenant: "t1", Account: "bob", IP: ip, Location: "SG", BankCard: card})
if !d.Allowed { /* d.Reason, d.RuleID say why */ }
```

### Evaluation order

1. **Rules unavailable → deny.** A store error, a rule set that fails to compile, a load timeout or a cancelled context all deny. `Check` returns a `Decision`, not `(Decision, error)`, so a caller cannot ignore an error and fall through to "allow".
2. **Allowlist, one dimension each: account, then nickname, then IP/CIDR.** The first hit allows, regardless of any deny rule.
3. **Deny rules, highest priority first.** A rule names any subset of account, nickname, IP/CIDR, IP location and bank card, and matches only when *all* of them match (AND). Ties are broken by rule ID so decisions are deterministic.
4. **Otherwise allow.**

Inputs are normalised: nicknames are lower-cased and trimmed, locations upper-cased, card numbers reduced to their digits, and IPv4-mapped IPv6 addresses unmapped (`::ffff:10.0.0.1` matches `10.0.0.0/8`). `Compile` rejects invalid rule sets, such as a deny rule with no conditions (it would deny everyone) or a bad CIDR. Call it when rules are written, so bad data never reaches the read path.

**Missing signals** are an explicit choice. By default, a condition on a field the request lacks (no location, say) does not match, so "deny location XX" lets a request with an unknown location through. `WithStrictSignals()` flips that and missing data denies. Neither default is right everywhere: strict mode turns a geo-IP outage into a login outage.

### Caching

Policies are compiled once per tenant and cached behind a `Cache` interface (a `MemoryCache` is included; a Redis one would store the rule set and recompile).

- **Concurrent misses share one load** (`singleflight`, keyed by tenant). The load runs with a context detached from the caller that started it (`context.WithoutCancel` plus its own timeout). Waiters use `DoChan` and select on their own context, so one caller giving up does not fail everyone who joined the flight.
- **Empty rule sets are cached.** Singleflight only merges *concurrent* misses. If "no rules" is not cached, a tenant with no rules reaches the store on every check, forever. The `Cache` interface separates "cached, empty" (`ok == true`) from a miss, and empty policies get a shorter TTL (`WithEmptyTTL`) so a first rule takes effect quickly even if an invalidation is lost.
- **Invalidation cannot be undone by an in-flight load.** In the classic cache-aside race, a load reads the old rules, an admin writes new rules and deletes the cache entry, then the load writes the old rules back. `Invalidate` bumps a per-tenant generation and calls `singleflight.Forget`, so new callers start a fresh load. A load re-checks the generation *after* its `Set` and deletes the entry if it changed. Checking after rather than before closes the window where the delete lands between the check and the write.
- **Cache errors fall back to the store.** The cache is an optimisation; a failing cache must not deny everyone.

The detached load context, empty-result caching and the post-`Set` generation check were each verified by removing them and watching their tests fail.

### Failure modes and trade-offs

| Situation | What happens | Alternatives |
|---|---|---|
| Store down | Cached tenants keep working until their TTL ends, then are denied | Serve stale on error (stale-if-error) with an age limit: better availability, weaker freshness |
| TTL expiry across many pods | One load per pod per tenant (singleflight is per process) | Jitter the TTL; refresh ahead of expiry |
| Several pods sharing one cache (e.g. Redis) | The generation guard is per process, so another pod's in-flight load can still write stale rules | Versioned cache keys, pub/sub invalidation, or a delayed second delete |
| Large rule sets | Deny rules are scanned in order: O(rules) per check. With 100 rules and none matching, a cached check takes 1.25 µs; 8 goroutines manage about 4M checks/s (M2, `make bench`) | Index rules by their most selective field |
| Allowlisted account | Never denied, even from a denied location | Intended for internal and support accounts; audit allowlist changes |

---

## idempotent: at-least-once consumer, once-only effects

Brokers redeliver messages after crashes, rebalances or retries, so duplicates
are normal. This package makes the *effect* of each message happen once:

```go
c := idempotent.NewConsumer(store,
	func(m idempotent.Message) (string, error) { return idempotent.Key("invoice-paid", invoiceID(m)), nil },
	handler,
	idempotent.WithRetry(3, idempotent.Backoff{Base: 100 * time.Millisecond, Max: 5 * time.Second, Jitter: 0.5}),
	idempotent.WithDeadLetter(dlq),
	idempotent.WithLanes(8),
)
err := c.Run(ctx, deliveries, func(m idempotent.Message, err error) { if err == nil { ack(m) } })
```

### The idempotency key

`Key(namespace, parts...)` hashes the operation and its business identity, for
example `("invoice-paid", invoiceID)`, into `invoice-paid:<32 hex>`. The key must come
from what the message *means*. A timestamp, a random ID generated at consume
time, or a delivery offset all change on redelivery and defeat the point.
Parts are length-prefixed before hashing, so `("ab","c")` and `("a","bc")`
differ.

### Record the key and the effect together

```
BEGIN
  INSERT INTO processed_messages (idempotency_key, ...) ... ON CONFLICT DO NOTHING
  0 rows? → already processed: ROLLBACK, report duplicate, ack
  handler writes its effect using the same transaction (sqlstore.Tx(ctx))
COMMIT
```

The ordering is the whole point:

- Record the key first, in its own transaction, then crash before the effect: **the effect is lost**. The redelivery is skipped as a duplicate.
- Apply the effect first, then crash before recording the key: **the effect happens twice**.
- Both in one transaction: either both commit or neither does.

When two consumers handle the same key at once (say, during a rebalance), they serialise on the primary key. The second insert waits for the first transaction and then inserts nothing. When the effect lives in *another* system, there is no shared transaction. Pass the idempotency key along as that system's request or transaction ID so it can de-duplicate on its side, which makes the scheme end-to-end.

`sqlstore` supports SQLite, PostgreSQL (`ON CONFLICT DO NOTHING`) and MySQL. For MySQL it uses `INSERT IGNORE`, not the no-op `ON DUPLICATE KEY UPDATE k = k`. With the driver's `CLIENT_FOUND_ROWS` flag on, the latter reports one affected row for a duplicate, which would look like a fresh insert. `INSERT IGNORE` instead turns errors such as truncation into warnings, which could silently merge two long keys, so keys longer than 128 bytes are rejected before the query. `Purge` deletes old keys. Keep them longer than the longest possible redelivery delay (broker retention plus any replay window), or a late duplicate is processed again. `examples/sqlite` runs all of this against a real SQLite database, including 20 concurrent attempts at one key.

### Retries and dead letters

| Failure | Handling | Acknowledged? |
|---|---|---|
| Handler error | Retry with capped exponential back-off and jitter; after the last attempt, dead-letter with every attempt's error joined | Yes, once dead-lettered |
| `Permanent(err)`, handler panic, or no derivable key | Dead-letter at once; retrying cannot help | Yes |
| Store or commit error (database down) | Retry; after the last attempt, **return an error, do not dead-letter** | No: the broker redelivers later |
| Dead-letter sink fails | Return an error | No |
| Context cancelled (shutdown) | Stop at once | No |

Treating store failures differently matters. If an outage were dead-lettered
like a bad message, a database blip would drain the whole topic into the DLQ.

### Ordering

`Run` routes each message to one of N lanes by an FNV hash of `Message.Key`
(the entity ID). One lane handles one message at a time, so messages about the
same entity are applied in order, while different entities run in parallel.
On Kafka, producers should use the same entity ID as the message key, so the
broker's per-partition order and the consumer's per-lane order agree. Messages
without a key are spread round-robin.

Trade-offs:

- **Head-of-line blocking.** A message being retried holds its lane, and so every key hashed to that lane, for up to the full retry schedule. That is the price of per-key order. Keep in-process retries short and leave long retries to a delay topic or a workflow engine.
- **Ordering after a dead letter.** Once a message for an entity is dead-lettered, later messages for that entity still run, so the entity may skip a step. A stricter design parks the key (sends its later messages to the DLQ too) until an operator resolves it.
- **Offset commits.** With lanes, a partition's messages finish out of order. Commit only up to the lowest unfinished offset per partition, which is not included here.

---

## Testing approach

- Table-driven unit tests in every package, all passing under `go test -race`.
- `FuzzRedact` with the three properties above, plus a `TestNoLeak` table that embeds one secret in a dozen shapes (headers, URLs, nested JSON, JSON inside a string).
- Concurrency tests built on fakes that block on channels, not on sleeps: singleflight collapsing 50 cold misses into one load, a cancelled leader with surviving waiters, and an invalidation landing mid-load.
- Integration tests against real SQLite, in a separate module: rollback of key and effect together, concurrent same-key attempts, purge, and an end-to-end replay of a batch three times.
- Testable examples in `redact`, `rules` and `idempotent` (`go test` checks their output) show the public APIs.

## Layout

```
redact/               io.Writer decorator, JSON walker, fuzz and benchmarks
rules/                policy compiler and engine with cache, singleflight, invalidation
idempotent/           key derivation, Store, MemoryStore, Consumer (retry, DLQ, lanes)
idempotent/sqlstore/  database/sql Store for SQLite, PostgreSQL and MySQL
examples/sqlite/      separate module: SQLite integration tests and a runnable demo
```

## Next steps

- `redact`: compile the merged regexp per set of keywords actually present, which would cut the slow path when a line triggers only one key.
- `rules`: a Redis `Cache` with versioned keys, and stale-if-error.
- `idempotent`: a per-partition offset watermark for committing with lanes; PostgreSQL and MySQL integration tests.

## License

MIT
