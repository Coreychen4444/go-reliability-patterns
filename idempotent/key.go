// Package idempotent processes messages from an at-least-once queue (Kafka,
// SQS, a database outbox) so that each message's effect is applied once.
//
// The broker may deliver a message more than once: after a consumer crash, a
// rebalance, or a retry that actually succeeded. The Consumer therefore:
//
//   - derives a deterministic idempotency key from the message's business
//     identity (Key), never from delivery metadata or the clock;
//   - runs the handler through a Store, which records the key with a
//     conflict-ignoring insert in the same transaction as the handler's
//     writes, and skips keys it has already recorded;
//   - retries failures with capped exponential back-off and jitter, and sends
//     messages that keep failing, or fail permanently, to a dead-letter sink;
//   - routes messages to lanes by entity key, so messages about one entity
//     are handled one at a time and in order while others run in parallel.
package idempotent

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// Key derives an idempotency key from a namespace (the operation, such as
// "invoice-paid") and the fields that identify one occurrence of it (such as
// the invoice ID). The same inputs always give the same key, so a redelivered
// message maps to the key recorded the first time.
//
// Each part is length-prefixed before hashing, so ("ab", "c") and ("a", "bc")
// give different keys. The result is the namespace, a colon and 32 hex
// characters (128 bits of SHA-256), short enough for an indexed column.
func Key(namespace string, parts ...string) string {
	h := sha256.New()
	var lenBuf [binary.MaxVarintLen64]byte
	for _, p := range append([]string{namespace}, parts...) {
		h.Write(binary.AppendUvarint(lenBuf[:0], uint64(len(p))))
		h.Write([]byte(p))
	}
	sum := h.Sum(nil)
	return namespace + ":" + hex.EncodeToString(sum[:16])
}
