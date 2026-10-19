package idempotent

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStoreOnce(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name     string
		calls    []error // fn's result on each call, in order
		wantDup  []bool
		wantRuns int
		wantLen  int
	}{
		{"first runs, second is a duplicate", []error{nil, nil}, []bool{false, true}, 1, 1},
		{"failure is not recorded", []error{boom, nil, nil}, []bool{false, false, true}, 2, 1},
		{"repeated failures keep running", []error{boom, boom}, []bool{false, false}, 2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemoryStore()
			runs := 0
			for i, result := range tt.calls {
				dup, err := s.Once(context.Background(), "k", func(context.Context) error {
					runs++
					return result
				})
				if dup != tt.wantDup[i] {
					t.Errorf("call %d: duplicate = %v, want %v", i, dup, tt.wantDup[i])
				}
				if !dup && !errors.Is(err, result) {
					t.Errorf("call %d: err = %v, want %v", i, err, result)
				}
			}
			if runs != tt.wantRuns || s.Len() != tt.wantLen {
				t.Errorf("runs = %d, recorded = %d; want %d, %d", runs, s.Len(), tt.wantRuns, tt.wantLen)
			}
		})
	}
}

func TestMemoryStorePanicReleasesKey(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.Once(context.Background(), "k", func(context.Context) error { panic("bad message") })
	if err == nil {
		t.Fatal("panicking fn returned no error")
	}
	dup, err := s.Once(context.Background(), "k", func(context.Context) error { return nil })
	if dup || err != nil {
		t.Fatalf("after a panic: duplicate = %v, err = %v; want the key free to run again", dup, err)
	}
}

func TestMemoryStoreConcurrentSameKey(t *testing.T) {
	s := NewMemoryStore()
	var runs, dups atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dup, err := s.Once(context.Background(), "k", func(context.Context) error {
				runs.Add(1)
				time.Sleep(time.Millisecond)
				return nil
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
	if runs.Load() != 1 || dups.Load() != 49 {
		t.Fatalf("runs = %d, duplicates = %d; want 1, 49", runs.Load(), dups.Load())
	}
}

func TestMemoryStoreWaiterCancelled(t *testing.T) {
	s := NewMemoryStore()
	started, release := make(chan struct{}), make(chan struct{})
	go func() {
		_, _ = s.Once(context.Background(), "k", func(context.Context) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Once(ctx, "k", func(context.Context) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter err = %v, want context.Canceled", err)
	}
	close(release)
}
