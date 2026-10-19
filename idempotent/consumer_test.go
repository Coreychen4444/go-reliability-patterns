package idempotent

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errTransient = errors.New("downstream timeout")

// scriptedHandler fails its first `fail` calls, then succeeds.
type scriptedHandler struct {
	fail      int
	permanent bool
	panics    bool
	calls     atomic.Int32
}

func (h *scriptedHandler) handle(context.Context, Message) error {
	n := h.calls.Add(1)
	switch {
	case h.panics:
		panic("nil map")
	case int(n) > h.fail:
		return nil
	case h.permanent:
		return Permanent(errors.New("payload does not parse"))
	default:
		return fmt.Errorf("attempt %d: %w", n, errTransient)
	}
}

// flakyStore fails its first `fail` calls before reaching fn.
type flakyStore struct {
	Store
	fail  int
	calls int
}

func (s *flakyStore) Once(ctx context.Context, key string, fn func(context.Context) error) (bool, error) {
	s.calls++
	if s.calls <= s.fail {
		return false, errors.New("too many connections")
	}
	return s.Store.Once(ctx, key, fn)
}

type deadLetters struct {
	mu       sync.Mutex
	err      error
	msgs     []Message
	attempts []int
	causes   []error
}

func (d *deadLetters) DeadLetter(_ context.Context, msg Message, attempts int, cause error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	d.msgs = append(d.msgs, msg)
	d.attempts = append(d.attempts, attempts)
	d.causes = append(d.causes, cause)
	return nil
}

func keyFromHeader(msg Message) (string, error) {
	id := msg.Headers["event-id"]
	if id == "" {
		return "", errors.New("no event-id header")
	}
	return Key("test-event", id), nil
}

func newTestConsumer(store Store, h Handler, opts ...Option) (*Consumer, *[]time.Duration) {
	c := NewConsumer(store, keyFromHeader, h, opts...)
	var delays []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error {
		delays = append(delays, d)
		return ctx.Err()
	}
	c.rand = func() float64 { return 0 }
	return c, &delays
}

func TestProcess(t *testing.T) {
	msg := Message{Topic: "invoices", Key: "inv-42", Headers: map[string]string{"event-id": "evt-1"}}
	backoff := Backoff{Base: 100 * time.Millisecond, Max: time.Second}
	tests := []struct {
		name      string
		handler   *scriptedHandler
		msg       Message
		storeFail int
		noDLQ     bool
		dlqErr    error

		wantErr      bool
		wantCalls    int32
		wantDLQ      []int // attempts reported for each dead letter
		wantDelays   []time.Duration
		wantStats    Stats
		causeContain string
	}{
		{
			name: "succeeds first time", handler: &scriptedHandler{}, msg: msg,
			wantCalls: 1, wantStats: Stats{Processed: 1},
		},
		{
			name: "transient failures, then success", handler: &scriptedHandler{fail: 2}, msg: msg,
			wantCalls: 3, wantDelays: []time.Duration{100 * time.Millisecond, 200 * time.Millisecond},
			wantStats: Stats{Processed: 1, Retries: 2},
		},
		{
			name: "retries exhausted: dead-lettered with every error", handler: &scriptedHandler{fail: 10}, msg: msg,
			wantCalls: 3, wantDLQ: []int{3}, wantDelays: []time.Duration{100 * time.Millisecond, 200 * time.Millisecond},
			wantStats: Stats{Retries: 2, DeadLettered: 1}, causeContain: "attempt 3",
		},
		{
			name: "permanent error: dead-lettered at once", handler: &scriptedHandler{fail: 10, permanent: true}, msg: msg,
			wantCalls: 1, wantDLQ: []int{1}, wantStats: Stats{DeadLettered: 1}, causeContain: "does not parse",
		},
		{
			name: "panic: dead-lettered at once", handler: &scriptedHandler{panics: true}, msg: msg,
			wantCalls: 1, wantDLQ: []int{1}, wantStats: Stats{DeadLettered: 1}, causeContain: "panicked",
		},
		{
			name: "no idempotency key: dead-lettered without calling the handler", handler: &scriptedHandler{}, msg: Message{Key: "inv-42"},
			wantCalls: 0, wantDLQ: []int{1}, wantStats: Stats{DeadLettered: 1}, causeContain: "event-id",
		},
		{
			name: "no dead-letter sink: not acknowledged", handler: &scriptedHandler{fail: 10}, msg: msg, noDLQ: true,
			wantErr: true, wantCalls: 3, wantDelays: []time.Duration{100 * time.Millisecond, 200 * time.Millisecond},
			wantStats: Stats{Retries: 2},
		},
		{
			name: "dead-letter sink fails: not acknowledged", handler: &scriptedHandler{fail: 10, permanent: true}, msg: msg, dlqErr: errors.New("dlq topic missing"),
			wantErr: true, wantCalls: 1,
		},
		{
			name: "store down: not dead-lettered, not acknowledged", handler: &scriptedHandler{}, msg: msg, storeFail: 10,
			wantErr: true, wantCalls: 0, wantDelays: []time.Duration{100 * time.Millisecond, 200 * time.Millisecond},
			wantStats: Stats{Retries: 2},
		},
		{
			name: "store recovers", handler: &scriptedHandler{}, msg: msg, storeFail: 1,
			wantCalls: 1, wantDelays: []time.Duration{100 * time.Millisecond}, wantStats: Stats{Processed: 1, Retries: 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dlq := &deadLetters{err: tt.dlqErr}
			opts := []Option{WithRetry(3, backoff)}
			if !tt.noDLQ {
				opts = append(opts, WithDeadLetter(dlq))
			}
			store := &flakyStore{Store: NewMemoryStore(), fail: tt.storeFail}
			c, delays := newTestConsumer(store, tt.handler.handle, opts...)

			err := c.Process(context.Background(), tt.msg)

			if (err != nil) != tt.wantErr {
				t.Errorf("Process error = %v, want error: %v", err, tt.wantErr)
			}
			if got := tt.handler.calls.Load(); got != tt.wantCalls {
				t.Errorf("handler called %d times, want %d", got, tt.wantCalls)
			}
			if fmt.Sprint(dlq.attempts) != fmt.Sprint(tt.wantDLQ) && !(len(dlq.attempts) == 0 && len(tt.wantDLQ) == 0) {
				t.Errorf("dead letters with attempts %v, want %v", dlq.attempts, tt.wantDLQ)
			}
			if tt.causeContain != "" && (len(dlq.causes) == 0 || !strings.Contains(dlq.causes[0].Error(), tt.causeContain)) {
				t.Errorf("dead-letter causes %v, want one containing %q", dlq.causes, tt.causeContain)
			}
			if fmt.Sprint(*delays) != fmt.Sprint(tt.wantDelays) && !(len(*delays) == 0 && len(tt.wantDelays) == 0) {
				t.Errorf("back-off delays %v, want %v", *delays, tt.wantDelays)
			}
			if got := c.Stats(); got != tt.wantStats {
				t.Errorf("stats %+v, want %+v", got, tt.wantStats)
			}
		})
	}
}

func TestDeadLetterKeepsEveryAttemptError(t *testing.T) {
	dlq := &deadLetters{}
	h := &scriptedHandler{fail: 10}
	c, _ := newTestConsumer(NewMemoryStore(), h.handle, WithRetry(3, Backoff{}), WithDeadLetter(dlq))
	if err := c.Process(context.Background(), Message{Headers: map[string]string{"event-id": "e"}}); err != nil {
		t.Fatal(err)
	}
	cause := dlq.causes[0]
	for i := 1; i <= 3; i++ {
		if !strings.Contains(cause.Error(), fmt.Sprintf("attempt %d", i)) {
			t.Errorf("cause %q is missing attempt %d", cause, i)
		}
	}
	if !errors.Is(cause, errTransient) {
		t.Errorf("cause %v does not wrap the handler error", cause)
	}
}

func TestDuplicateDeliveryIsSkipped(t *testing.T) {
	h := &scriptedHandler{}
	c, _ := newTestConsumer(NewMemoryStore(), h.handle)
	msg := Message{Headers: map[string]string{"event-id": "evt-7"}}
	for i := 0; i < 3; i++ {
		if err := c.Process(context.Background(), msg); err != nil {
			t.Fatal(err)
		}
	}
	if h.calls.Load() != 1 || c.Stats() != (Stats{Processed: 1, Duplicates: 2}) {
		t.Fatalf("handler calls = %d, stats = %+v; want 1 call, 1 processed, 2 duplicates", h.calls.Load(), c.Stats())
	}
}

func TestProcessStopsWhenCancelledDuringBackoff(t *testing.T) {
	dlq := &deadLetters{}
	h := &scriptedHandler{fail: 10}
	c := NewConsumer(NewMemoryStore(), keyFromHeader, h.handle, WithDeadLetter(dlq),
		WithRetry(5, Backoff{Base: time.Hour, Max: time.Hour}))
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for h.calls.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	err := c.Process(ctx, Message{Headers: map[string]string{"event-id": "e"}})
	if !errors.Is(err, context.Canceled) || len(dlq.msgs) != 0 {
		t.Fatalf("err = %v, dead letters = %d; want context.Canceled and none", err, len(dlq.msgs))
	}
}

func TestBackoffDelay(t *testing.T) {
	ms := time.Millisecond
	tests := []struct {
		name string
		b    Backoff
		n    int
		r    float64
		want time.Duration
	}{
		{"first retry", Backoff{Base: 100 * ms, Max: time.Second}, 1, 0, 100 * ms},
		{"doubles", Backoff{Base: 100 * ms, Max: time.Second}, 3, 0, 400 * ms},
		{"capped", Backoff{Base: 100 * ms, Max: time.Second}, 5, 0, time.Second},
		{"capped far out", Backoff{Base: 100 * ms, Max: time.Second}, 60, 0, time.Second},
		{"no cap", Backoff{Base: 100 * ms}, 4, 0, 800 * ms},
		{"no cap does not overflow", Backoff{Base: time.Hour}, 200, 0, time.Duration(1<<63 - 1)},
		{"full jitter", Backoff{Base: 100 * ms, Max: time.Second, Jitter: 1}, 2, 0.5, 100 * ms},
		{"half jitter", Backoff{Base: 100 * ms, Max: time.Second, Jitter: 0.5}, 2, 0.5, 150 * ms},
		{"jitter clamped", Backoff{Base: 100 * ms, Max: time.Second, Jitter: 3}, 1, 0.5, 50 * ms},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.b.Delay(tt.n, tt.r); got != tt.want {
				t.Errorf("Delay(%d, %v) = %v, want %v", tt.n, tt.r, got, tt.want)
			}
		})
	}
}

// Run must hand a key's messages to the handler one at a time and in order,
// while different keys proceed in parallel.
func TestRunPreservesPerKeyOrder(t *testing.T) {
	const keys, perKey = 20, 50
	var (
		mu       sync.Mutex
		seen     = make(map[string][]int)
		inFlight = make(map[string]int)
		active   atomic.Int32
		peak     atomic.Int32
	)
	handler := func(_ context.Context, msg Message) error {
		mu.Lock()
		inFlight[msg.Key]++
		overlap := inFlight[msg.Key] > 1
		mu.Unlock()
		if overlap {
			t.Errorf("two messages for %s ran at the same time", msg.Key)
		}
		for n := active.Add(1); ; {
			if p := peak.Load(); n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(time.Duration(rand.IntN(200)) * time.Microsecond)
		active.Add(-1)

		seq, _ := strconv.Atoi(msg.Headers["seq"])
		mu.Lock()
		seen[msg.Key] = append(seen[msg.Key], seq)
		inFlight[msg.Key]--
		mu.Unlock()
		return nil
	}
	c := NewConsumer(NewMemoryStore(), keyFromHeader, handler, WithLanes(4))

	in := make(chan Message)
	var acked atomic.Int32
	runErr := make(chan error)
	go func() {
		runErr <- c.Run(context.Background(), in, func(msg Message, err error) {
			if err != nil {
				t.Errorf("message %v: %v", msg.Headers, err)
			}
			acked.Add(1)
		})
	}()
	for seq := 0; seq < perKey; seq++ {
		for k := 0; k < keys; k++ {
			key := fmt.Sprintf("account-%d", k)
			in <- Message{Key: key, Headers: map[string]string{
				"event-id": fmt.Sprintf("%s/%d", key, seq),
				"seq":      strconv.Itoa(seq),
			}}
		}
	}
	close(in)
	if err := <-runErr; err != nil {
		t.Fatal(err)
	}

	if acked.Load() != keys*perKey {
		t.Fatalf("acked %d messages, want %d", acked.Load(), keys*perKey)
	}
	for key, seqs := range seen {
		for i, s := range seqs {
			if s != i {
				t.Fatalf("%s: processed in order %v", key, seqs)
			}
		}
	}
	if peak.Load() < 2 {
		t.Errorf("peak concurrency %d: lanes did not run in parallel", peak.Load())
	}
}

// Replaying a batch, as a broker does after a consumer restarts from an older
// offset, must not apply anything twice.
func TestRedeliveredBatchIsAppliedOnce(t *testing.T) {
	var mu sync.Mutex
	balance := map[string]int{}
	credit := func(_ context.Context, msg Message) error {
		amount, _ := strconv.Atoi(string(msg.Value))
		mu.Lock()
		balance[msg.Key] += amount
		mu.Unlock()
		return nil
	}
	c := NewConsumer(NewMemoryStore(), keyFromHeader, credit, WithLanes(3))

	var batch []Message
	want := map[string]int{}
	for i := 0; i < 30; i++ {
		acct := fmt.Sprintf("acct-%d", i%5)
		batch = append(batch, Message{Key: acct, Value: []byte(strconv.Itoa(i + 1)), Headers: map[string]string{"event-id": fmt.Sprintf("credit-%d", i)}})
		want[acct] += i + 1
	}
	deliveries := append(append([]Message{}, batch...), batch...) // the whole batch, twice
	deliveries = append(deliveries, batch[3:9]...)                // and part of it a third time

	in := make(chan Message, len(deliveries))
	for _, m := range deliveries {
		in <- m
	}
	close(in)
	if err := c.Run(context.Background(), in, nil); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(balance) != fmt.Sprint(want) {
		t.Fatalf("balances %v, want %v", balance, want)
	}
	if s := c.Stats(); s.Processed != 30 || s.Duplicates != int64(len(deliveries)-30) {
		t.Fatalf("stats %+v, want 30 processed and %d duplicates", s, len(deliveries)-30)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	block := make(chan struct{})
	handler := func(ctx context.Context, _ Message) error {
		<-block
		return ctx.Err()
	}
	c := NewConsumer(NewMemoryStore(), keyFromHeader, handler)
	ctx, cancel := context.WithCancel(context.Background())
	in := make(chan Message)
	var mu sync.Mutex
	var results []error
	runErr := make(chan error)
	go func() {
		runErr <- c.Run(ctx, in, func(_ Message, err error) {
			mu.Lock()
			results = append(results, err)
			mu.Unlock()
		})
	}()
	in <- Message{Key: "a", Headers: map[string]string{"event-id": "1"}}
	cancel()
	close(block)
	if err := <-runErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, err := range results {
		if err == nil {
			t.Errorf("a message was acknowledged after cancellation")
		}
	}
}
