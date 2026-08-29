package deception

import (
	"crypto/rand"
	"testing"
	"time"
)

func newTestTarpit(t *testing.T) *Tarpit {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	return NewTarpit(key, time.Hour)
}

func TestTarpit_AcceptReturnsCookie(t *testing.T) {
	tp := newTestTarpit(t)
	connID, cookie, err := tp.Accept(42)
	if err != nil {
		t.Fatalf("Accept err = %v", err)
	}
	if connID == 0 {
		t.Error("connID is 0")
	}
	if cookie == [32]byte{} {
		t.Error("cookie is zero")
	}
	if tp.Len() != 1 {
		t.Errorf("Len = %d, want 1", tp.Len())
	}
}

func TestTarpit_VerifySuccess(t *testing.T) {
	tp := newTestTarpit(t)
	connID, cookie, err := tp.Accept(7)
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.Verify(connID, cookie); err != nil {
		t.Errorf("Verify err = %v, want nil", err)
	}
}

func TestTarpit_VerifyBadCookie(t *testing.T) {
	tp := newTestTarpit(t)
	connID, _, err := tp.Accept(7)
	if err != nil {
		t.Fatal(err)
	}
	var badCookie [32]byte
	badCookie[0] = 0xFF
	if err := tp.Verify(connID, badCookie); err != ErrBadCookie {
		t.Errorf("Verify err = %v, want ErrBadCookie", err)
	}
}

func TestTarpit_VerifyUnknownConn(t *testing.T) {
	tp := newTestTarpit(t)
	var cookie [32]byte
	if err := tp.Verify(0xDEADBEEF, cookie); err != ErrUnknownConnID {
		t.Errorf("Verify err = %v, want ErrUnknownConnID", err)
	}
}

func TestTarpit_ExhaustionEvictsLRU(t *testing.T) {
	tp := newTestTarpit(t)
	// Accept MaxEntries connections.
	connIDs := make([]uint64, 0, MaxEntries)
	cookies := make([][32]byte, 0, MaxEntries)
	for i := 0; i < MaxEntries; i++ {
		id, cookie, err := tp.Accept(uint32(i + 1))
		if err != nil {
			t.Fatalf("Accept %d: %v", i, err)
		}
		connIDs = append(connIDs, id)
		cookies = append(cookies, cookie)
	}
	if tp.Len() != MaxEntries {
		t.Errorf("Len = %d, want %d", tp.Len(), MaxEntries)
	}
	// Accept one more: should evict the oldest.
	extraID, extraCookie, err := tp.Accept(99999)
	if err != nil {
		t.Fatalf("Accept overflow: %v", err)
	}
	if tp.Len() != MaxEntries {
		t.Errorf("Len after overflow = %d, want %d", tp.Len(), MaxEntries)
	}
	// The first connection should now be
	// unknown (evicted).
	if err := tp.Verify(connIDs[0], cookies[0]); err != ErrUnknownConnID {
		t.Errorf("Verify evicted conn: err = %v, want ErrUnknownConnID", err)
	}
	// The new connection should verify.
	if err := tp.Verify(extraID, extraCookie); err != nil {
		t.Errorf("Verify new conn: err = %v, want nil", err)
	}
}

func TestTarpit_ExhaustionCapsAtMax(t *testing.T) {
	tp := newTestTarpit(t)
	// The acquireSlot() function NEVER
	// refuses: it always evicts. So we
	// cannot trigger ErrTooManyConnections.
	// Instead, we assert that the table
	// never exceeds MaxEntries even under
	// sustained Accept pressure.
	for i := 0; i < MaxEntries*2; i++ {
		_, _, err := tp.Accept(uint32(i + 1))
		if err != nil {
			t.Fatalf("Accept %d: %v", i, err)
		}
		if tp.Len() > MaxEntries {
			t.Fatalf("Len = %d, want <= %d", tp.Len(), MaxEntries)
		}
	}
}

func TestTarpit_TTLRelease(t *testing.T) {
	var key [32]byte
	tp := NewTarpit(key, 100*time.Millisecond)
	// Fake clock: start at t0, advance on demand.
	nowNS := time.Now().UnixNano()
	tp.SetNow(func() time.Time { return time.Unix(0, nowNS) })
	connID, cookie, err := tp.Accept(1)
	if err != nil {
		t.Fatal(err)
	}
	// Verify at t0: OK.
	if err := tp.Verify(connID, cookie); err != nil {
		t.Errorf("Verify t0: err = %v, want nil", err)
	}
	// Advance 200ms; sweep; entry reaped.
	nowNS += int64(200 * time.Millisecond)
	if n := tp.Sweep(); n != 1 {
		t.Errorf("Sweep reaped = %d, want 1", n)
	}
	// Verify after reaping: ErrUnknownConnID
	// (entry was removed from the table).
	if err := tp.Verify(connID, cookie); err != ErrUnknownConnID {
		t.Errorf("Verify after sweep: err = %v, want ErrUnknownConnID", err)
	}
}

func TestTarpit_VerifyAfterTTL(t *testing.T) {
	var key [32]byte
	tp := NewTarpit(key, 50*time.Millisecond)
	nowNS := time.Now().UnixNano()
	tp.SetNow(func() time.Time { return time.Unix(0, nowNS) })
	connID, cookie, err := tp.Accept(1)
	if err != nil {
		t.Fatal(err)
	}
	// Advance past TTL.
	nowNS += int64(100 * time.Millisecond)
	// Verify: should return ErrExpiredConn
	// (entry exists but is too old).
	if err := tp.Verify(connID, cookie); err != ErrExpiredConn {
		t.Errorf("Verify after TTL: err = %v, want ErrExpiredConn", err)
	}
	// The entry should now be released.
	if tp.Len() != 0 {
		t.Errorf("Len after expired verify = %d, want 0", tp.Len())
	}
}

func TestTarpit_Release(t *testing.T) {
	tp := newTestTarpit(t)
	connID, _, err := tp.Accept(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.Release(connID); err != nil {
		t.Errorf("Release err = %v, want nil", err)
	}
	if tp.Len() != 0 {
		t.Errorf("Len after Release = %d, want 0", tp.Len())
	}
	if err := tp.Release(connID); err != ErrUnknownConnID {
		t.Errorf("Release double: err = %v, want ErrUnknownConnID", err)
	}
}

func TestTarpit_Concurrent(t *testing.T) {
	tp := newTestTarpit(t)
	const N = 100
	type result struct {
		connID uint64
		cookie [32]byte
		err    error
	}
	resCh := make(chan result, N)
	for i := 0; i < N; i++ {
		go func() {
			id, c, err := tp.Accept(1)
			resCh <- result{id, c, err}
		}()
	}
	for i := 0; i < N; i++ {
		r := <-resCh
		if r.err != nil {
			t.Errorf("Accept err = %v", r.err)
		}
		if r.connID == 0 {
			t.Error("connID is 0")
		}
	}
}

// TestTarpit_AcceptAllocation documents the
// allocation profile of Accept. Unlike the
// hot-path timing/EFSM/engine tests, Accept
// is on the per-connection cold path: a
// tarpit connection is created at most a
// few times per second per attacker. Three
// allocations (one for the interface box in
// the pool, two for the hmac internal
// scratch) are acceptable here.
//
// We assert the allocation count is
// BOUNDED (< 5) so a future refactor that
// accidentally introduces unbounded growth
// (e.g. fmt.Sprintf, json.Marshal) is caught.
func TestTarpit_AcceptAllocation(t *testing.T) {
	var key [32]byte
	tp := NewTarpit(key, time.Hour)
	_, _, _ = tp.Accept(1)
	allocs := testing.AllocsPerRun(1000, func() {
		_, _, _ = tp.Accept(2)
	})
	if allocs > 5 {
		t.Errorf("Accept allocates %v allocs/op, want <= 5 (cold path)", allocs)
	}
}
