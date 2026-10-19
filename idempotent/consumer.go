package idempotent

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// A Message is one delivery from the broker.
type Message struct {
	Topic   string
	Key     string // entity ID; messages with the same Key are processed in order
	Value   []byte
	Headers map[string]string
}

// A Handler applies a message's effect. It may be called more than once for
// the same message if an earlier attempt failed, but never again after it has
// succeeded.
type Handler func(ctx context.Context, msg Message) error

// A KeyFunc derives a message's idempotency key, normally with Key.
type KeyFunc func(msg Message) (string, error)

// A DeadLetterSink receives messages that could not be processed. cause joins
// the error from every attempt.
type DeadLetterSink interface {
	DeadLetter(ctx context.Context, msg Message, attempts int, cause error) error
}

// DeadLetterFunc adapts a function to DeadLetterSink.
type DeadLetterFunc func(ctx context.Context, msg Message, attempts int, cause error) error

// DeadLetter calls f.
func (f DeadLetterFunc) DeadLetter(ctx context.Context, msg Message, attempts int, cause error) error {
	return f(ctx, msg, attempts, cause)
}

// Permanent marks err as not worth retrying, such as a payload that does not
// parse. The message goes to the dead-letter sink after one attempt.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err}
}

type permanentError struct{ err error }

func (e *permanentError) Error() string { return "permanent: " + e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// IsPermanent reports whether err, or an error it wraps, was marked Permanent.
func IsPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

// Backoff computes retry delays: Base before the first retry, doubling each
// time, capped at Max.
type Backoff struct {
	Base time.Duration
	Max  time.Duration
	// Jitter is the fraction of each delay that is randomised. 0 gives fixed
	// delays; 1 gives "full jitter", uniform in [0, delay]. Jitter spreads
	// out retries from consumers that failed at the same moment.
	Jitter float64
}

// Delay returns the delay before retry n (n >= 1), given a random number r
// in [0, 1). A Max of zero or less means no cap.
func (b Backoff) Delay(n int, r float64) time.Duration {
	limit := b.Max
	if limit <= 0 {
		limit = math.MaxInt64
	}
	d := b.Base
	for i := 1; i < n && d < limit; i++ {
		if d > limit/2 { // doubling would pass the cap, or overflow
			d = limit
		} else {
			d *= 2
		}
	}
	d = min(d, limit)
	jitter := min(max(b.Jitter, 0), 1)
	return d - time.Duration(float64(d)*jitter*r)
}

// Stats counts what a Consumer has done.
type Stats struct {
	Processed    int64 // handler succeeded
	Duplicates   int64 // skipped: idempotency key already recorded
	Retries      int64 // attempts after the first
	DeadLettered int64
}

// A Consumer processes messages at least once with idempotent effects. Create
// one with NewConsumer.
type Consumer struct {
	store       Store
	key         KeyFunc
	handler     Handler
	deadLetter  DeadLetterSink
	maxAttempts int
	backoff     Backoff
	lanes       int
	laneBuffer  int

	sleep func(context.Context, time.Duration) error
	rand  func() float64

	processed, duplicates, retries, deadLettered atomic.Int64
}

// An Option configures a Consumer.
type Option func(*Consumer)

// WithRetry sets the total number of attempts per message (default 3) and the
// back-off between them (default 100ms doubling to 5s, half jittered).
func WithRetry(maxAttempts int, b Backoff) Option {
	return func(c *Consumer) { c.maxAttempts, c.backoff = max(maxAttempts, 1), b }
}

// WithDeadLetter sets where messages go after their last failed attempt.
// Without one, such a message is returned as an error and never
// acknowledged, so the broker redelivers it forever and it blocks its key.
func WithDeadLetter(s DeadLetterSink) Option { return func(c *Consumer) { c.deadLetter = s } }

// WithLanes sets how many messages Run processes in parallel (default 1).
func WithLanes(n int) Option { return func(c *Consumer) { c.lanes = max(n, 1) } }

// NewConsumer returns a Consumer that records keys in store, derives them with
// key and applies messages with h.
func NewConsumer(store Store, key KeyFunc, h Handler, opts ...Option) *Consumer {
	c := &Consumer{
		store:       store,
		key:         key,
		handler:     h,
		maxAttempts: 3,
		backoff:     Backoff{Base: 100 * time.Millisecond, Max: 5 * time.Second, Jitter: 0.5},
		lanes:       1,
		laneBuffer:  16,
		sleep:       sleep,
		rand:        rand.Float64,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Stats returns a snapshot of the consumer's counters.
func (c *Consumer) Stats() Stats {
	return Stats{
		Processed:    c.processed.Load(),
		Duplicates:   c.duplicates.Load(),
		Retries:      c.retries.Load(),
		DeadLettered: c.deadLettered.Load(),
	}
}

// Process handles one delivery. A nil result means the message is finished
// (applied, skipped as a duplicate, or dead-lettered) and can be acknowledged.
// An error means it must not be acknowledged: the context ended, the store
// was unavailable through every attempt, or the dead-letter sink failed. The
// broker will redeliver it, and the idempotency key makes that safe.
func (c *Consumer) Process(ctx context.Context, msg Message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := c.key(msg)
	if err != nil {
		return c.sendToDeadLetter(ctx, msg, 1, Permanent(fmt.Errorf("derive idempotency key: %w", err)))
	}

	var errs []error
	for attempt := 1; ; attempt++ {
		var handlerErr error
		dup, err := c.store.Once(ctx, key, func(ctx context.Context) error {
			handlerErr = c.call(ctx, msg)
			return handlerErr
		})
		switch {
		case err == nil && dup:
			c.duplicates.Add(1)
			return nil
		case err == nil:
			c.processed.Add(1)
			return nil
		case ctx.Err() != nil:
			return ctx.Err() // shutting down: leave the message for redelivery
		}

		errs = append(errs, err)
		last := attempt >= c.maxAttempts
		switch {
		case handlerErr == nil && last:
			// The store (or the commit) failed, not the message. Dead-lettering
			// would empty the topic into the DLQ during a database outage, so
			// leave the message unacknowledged instead.
			return fmt.Errorf("idempotent: store unavailable after %d attempts: %w", attempt, errors.Join(errs...))
		case handlerErr != nil && (last || IsPermanent(handlerErr)):
			return c.sendToDeadLetter(ctx, msg, attempt, errors.Join(errs...))
		}
		c.retries.Add(1)
		if err := c.sleep(ctx, c.backoff.Delay(attempt, c.rand())); err != nil {
			return err
		}
	}
}

// call runs the handler and turns a panic into a permanent error, so one bad
// message cannot crash the consumer or leave the store's record half-made.
func (c *Consumer) call(ctx context.Context, msg Message) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = Permanent(fmt.Errorf("handler panicked: %v", r))
		}
	}()
	return c.handler(ctx, msg)
}

func (c *Consumer) sendToDeadLetter(ctx context.Context, msg Message, attempts int, cause error) error {
	if c.deadLetter == nil {
		return fmt.Errorf("idempotent: giving up after %d attempts (no dead-letter sink): %w", attempts, cause)
	}
	if err := c.deadLetter.DeadLetter(ctx, msg, attempts, cause); err != nil {
		return fmt.Errorf("idempotent: dead-letter failed: %w (after: %w)", err, cause)
	}
	c.deadLettered.Add(1)
	return nil
}

// Run reads messages from in and processes them until in is closed or ctx
// ends. Messages with the same Key always go to the same lane and are
// processed one at a time, in the order received; messages with different
// keys run in parallel on up to the configured number of lanes. Messages with
// no Key are spread round-robin. done, if not nil, is called after each
// message with Process's result; acknowledge the message when it is nil.
//
// A message being retried holds up its lane, and so every key that hashes to
// that lane, for at most the full retry schedule. That is the price of
// per-key order: a later message for the same entity must not overtake it.
func (c *Consumer) Run(ctx context.Context, in <-chan Message, done func(Message, error)) error {
	lanes := make([]chan Message, c.lanes)
	var wg sync.WaitGroup
	for i := range lanes {
		lanes[i] = make(chan Message, c.laneBuffer)
		wg.Add(1)
		go func(lane <-chan Message) {
			defer wg.Done()
			for msg := range lane {
				err := c.Process(ctx, msg)
				if done != nil {
					done(msg, err)
				}
			}
		}(lanes[i])
	}
	defer func() {
		for _, lane := range lanes {
			close(lane)
		}
		wg.Wait()
	}()

	next := 0 // round-robin position for messages without a key
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-in:
			if !ok {
				return nil
			}
			i := next % len(lanes)
			if msg.Key != "" {
				i = laneFor(msg.Key, len(lanes))
			} else {
				next++
			}
			select {
			case lanes[i] <- msg:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func laneFor(key string, n int) int {
	h := fnv.New32a()
	h.Write([]byte(key))
	return int(h.Sum32() % uint32(n))
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
