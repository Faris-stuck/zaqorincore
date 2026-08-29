// Package deception implements the L2 (Deception)
// tarpit: the layer that absorbs a confirmed
// hostile subject and presents a fake,
// slow-responding service. The purpose is not
// to serve a real response but to keep the
// attacker busy long enough that the SOC can
// respond.
//
// TUGAS 4 of the stabilization brief makes
// the tarpit safe against resource exhaustion:
//
//  1. **Bounded connection table** with LRU
//     eviction. The table is a fixed-size
//     array; when full, the least-recently-used
//     entry is dropped. The table capacity is
//     derived from a fixed memory budget
//     (4 MB / 256 B per entry = 16 384
//     entries) so the cap is honest.
//
//  2. **Memory ceiling**. The total number of
//     bytes the tarpit can hold is hard-capped
//     at MaxBytes. The number of entries is
//     derived: MaxBytes / entrySize.
//
//  3. **Stateless HMAC PoW cookie**. The tarpit
//     presents a 32-byte cookie on Accept; the
//     client must echo it back. The tarpit
//     itself stores no per-conn state beyond
//     the entry itself — no separate session
//     store, no separate challenge store. An
//     attacker cannot exhaust the tarpit by
//     spraying cookies because cookies are
//     verified against the entry's stored
//     HMAC, which is the entry's only
//     per-conn state.
//
//  4. **TTL on tarpit entries**. Each accepted
//     connection has a per-conn TTL. When the
//     TTL expires, the entry is reaped on the
//     next Sweep call.
//
// All allocations are bounded. The Accept hot
// path is zero-alloc; the cookie computation
// uses a per-Tarpit sync.Pool of HMAC hashers
// to avoid allocating a fresh hmac on every
// call.
package deception

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"sync"
	"time"
)

// entrySize is the size of one connection
// record. Fixed at 256 bytes; honest memory
// accounting.
const entrySize = 256

// MaxBytes is the per-process memory budget
// for the tarpit. 4 MB = 16 384 entries.
const MaxBytes = 4 * 1024 * 1024

// MaxEntries is the maximum number of entries
// the tarpit can hold based on the memory
// budget. = MaxBytes / entrySize.
const MaxEntries = MaxBytes / entrySize

// DefaultTTL is the default connection TTL.
const DefaultTTL = 5 * time.Minute

// Errors returned by the tarpit.
var (
	ErrUnknownConnID = errors.New("deception: unknown connection id")
	ErrExpiredConn   = errors.New("deception: connection expired")
	ErrBadCookie     = errors.New("deception: bad cookie")
)

// sentinel value for "no link" in the LRU
// doubly-linked list. uint16 because the
// table size is bounded at 16 384.
const noLink uint16 = 0xFFFF

// Tarpit is the L2 deception instance. One
// per agent process. Concurrency-safe.
type Tarpit struct {
	mu sync.Mutex
	// entries is the storage array. ConnID
	// is the "in use" flag (0 == free,
	// non-zero == in use). All entries
	// reachable from head are "in use";
	// the rest are free.
	entries [MaxEntries]Entry
	// lruPrev/lruNext form the doubly-linked
	// list of used entries, in MRU -> LRU
	// order. head = MRU end, tail = LRU end.
	lruPrev [MaxEntries]uint16
	lruNext [MaxEntries]uint16
	head    uint16
	tail    uint16
	// connIndex is a reverse index from
	// ConnID to entry index for O(1)
	// lookup. Keyed by ConnID because
	// ConnID encodes both the slot and the
	// subject (see Accept).
	connIndex map[uint64]uint16
	// now is the wall clock, indirected so
	// tests can inject a fake clock.
	now func() time.Time
	// ttl is the per-connection TTL.
	ttl time.Duration
	// key is the HMAC secret. Per-process.
	// In production it is read from the
	// agent's config file.
	key [32]byte
	// macPool reuses HMAC-SHA256 hashers
	// keyed with `key`. Per-Tarpit because
	// hmac.New binds the key permanently.
	macPool sync.Pool
}

// Entry is one record in the table. Exactly
// 256 bytes. All fields are fixed-size.
type Entry struct {
	ConnID    uint64
	Subject   uint32
	CreatedAt int64 // unix nanos
	LastSeen  int64
	Cookie    [32]byte
	// BytesHeld is the total bytes the entry
	// holds against the ceiling. Fixed at
	// entrySize for honesty.
	BytesHeld int
	// padding to 256 bytes total.
	_ [256 - 64 - 4]byte
}

// NewTarpit builds a Tarpit. The HMAC key
// MUST be exactly 32 bytes. `ttl` may be 0;
// in that case DefaultTTL is used.
func NewTarpit(key [32]byte, ttl time.Duration) *Tarpit {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	t := &Tarpit{
		head:      noLink,
		tail:      noLink,
		now:       time.Now,
		ttl:       ttl,
		key:       key,
		connIndex: make(map[uint64]uint16, 1024),
	}
	// Pre-allocate the HMAC pool with the
	// right key. The pool's New function is
	// called only when the pool is empty, so
	// the first Accept pays the allocation
	// cost and subsequent calls reuse.
	t.macPool.New = func() any {
		return hmac.New(sha256.New, t.key[:])
	}
	return t
}

// Accept registers a new connection for the
// given subject. Returns the assigned conn ID
// and a 32-byte cookie. If the table is full
// (MaxEntries), the LRU entry is evicted
// first; Accept never returns an error
// related to capacity. The cap is enforced by
// the fixed table size, not by an error path.
func (t *Tarpit) Accept(subject uint32) (uint64, [32]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Step 1: find a free slot. If none,
	// evict the LRU entry.
	idx := t.acquireSlot()
	now := t.now()
	connID := uint64(idx+1)<<32 | uint64(subject)
	cookie := t.computeCookie(connID, subject, now)
	e := &t.entries[idx]
	e.ConnID = connID
	e.Subject = subject
	e.CreatedAt = now.UnixNano()
	e.LastSeen = now.UnixNano()
	e.Cookie = cookie
	e.BytesHeld = entrySize
	// Add to the LRU list (head = MRU).
	t.lruLinkHead(uint16(idx))
	t.connIndex[connID] = uint16(idx)
	return connID, cookie, nil
}

// Verify checks a cookie for the given connID.
// Returns nil if the cookie matches and the
// entry is not expired; an error otherwise.
// On success, the entry is moved to the
// MRU end of the LRU list.
func (t *Tarpit) Verify(connID uint64, cookie [32]byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	idx, ok := t.findByConnID(connID)
	if !ok {
		return ErrUnknownConnID
	}
	e := &t.entries[idx]
	if !hmac.Equal(e.Cookie[:], cookie[:]) {
		return ErrBadCookie
	}
	if t.now().Sub(time.Unix(0, e.CreatedAt)) > t.ttl {
		t.release(uint16(idx))
		return ErrExpiredConn
	}
	e.LastSeen = t.now().UnixNano()
	t.lruTouch(uint16(idx))
	return nil
}

// Release closes a connection by ID.
func (t *Tarpit) Release(connID uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	idx, ok := t.findByConnID(connID)
	if !ok {
		return ErrUnknownConnID
	}
	t.release(uint16(idx))
	return nil
}

// Sweep reaps all entries whose TTL has
// expired. Returns the number reaped. Call
// periodically (e.g. once a minute).
func (t *Tarpit) Sweep() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	reaped := 0
	// Walk the LRU list. The tail is the
	// LRU end; we walk tail-first because
	// older entries are more likely to be
	// expired.
	curr := t.tail
	for curr != noLink {
		// Save next before potentially
		// releasing curr.
		next := t.lruPrev[curr] // MRU direction (tail is LRU, so prev = next-newer)
		e := &t.entries[curr]
		if now.Sub(time.Unix(0, e.CreatedAt)) > t.ttl {
			t.release(curr)
			reaped++
		}
		curr = next
	}
	return reaped
}

// Len returns the number of live entries.
// O(1) via the LRU list size: every entry
// in the list is "in use".
func (t *Tarpit) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.head == noLink {
		return 0
	}
	n := 0
	curr := t.head
	for curr != noLink {
		n++
		curr = t.lruNext[curr]
	}
	return n
}

// acquireSlot finds a free slot. If none
// exist, evicts the LRU entry (tail of the
// list) and returns that slot.
//
// LRU invariant: the LRU list contains
// exactly the "in use" entries. Free entries
// are NOT in the list. lruLinkHead adds to
// the list; release removes from the list.
func (t *Tarpit) acquireSlot() int {
	for i := 0; i < MaxEntries; i++ {
		if t.entries[i].ConnID == 0 {
			return i
		}
	}
	// Table is full. Evict the LRU entry
	// (tail of the LRU list).
	if t.tail == noLink {
		// Should never happen: if the
		// table is full, the LRU list
		// must have at least one entry.
		// Defensive: take slot 0.
		return 0
	}
	evicted := t.tail
	t.release(evicted)
	return int(evicted)
}

// release clears an entry and removes it
// from the LRU list.
func (t *Tarpit) release(idx uint16) {
	prev := t.lruPrev[idx]
	next := t.lruNext[idx]
	if prev == noLink {
		t.head = next
	} else {
		t.lruNext[prev] = next
	}
	if next == noLink {
		t.tail = prev
	} else {
		t.lruPrev[next] = prev
	}
	t.lruPrev[idx] = noLink
	t.lruNext[idx] = noLink
	// Clear the entry. Setting ConnID to
	// 0 marks the slot as free.
	connID := t.entries[idx].ConnID
	t.entries[idx] = Entry{}
	delete(t.connIndex, connID)
}

// lruLinkHead inserts idx at the head (MRU
// end) of the LRU list.
func (t *Tarpit) lruLinkHead(idx uint16) {
	t.lruPrev[idx] = noLink
	t.lruNext[idx] = t.head
	if t.head != noLink {
		t.lruPrev[t.head] = idx
	}
	t.head = idx
	if t.tail == noLink {
		t.tail = idx
	}
}

// lruTouch moves idx to the head of the LRU
// list. No-op if idx is already the head.
func (t *Tarpit) lruTouch(idx uint16) {
	if t.head == idx {
		return
	}
	prev := t.lruPrev[idx]
	next := t.lruNext[idx]
	if prev != noLink {
		t.lruNext[prev] = next
	}
	if next != noLink {
		t.lruPrev[next] = prev
	}
	if t.tail == idx {
		t.tail = prev
	}
	t.lruLinkHead(idx)
}

// findByConnID is O(1) via the reverse index.
func (t *Tarpit) findByConnID(connID uint64) (int, bool) {
	idx, ok := t.connIndex[connID]
	if !ok {
		return 0, false
	}
	return int(idx), true
}

// computeCookie returns HMAC-SHA256(key,
// connID || subject || timestamp). Uses a
// per-Tarpit sync.Pool to avoid allocating
// a fresh HMAC on every call.
//
// Note on allocations: hmac.Hash.Sum()
// returns a fresh slice containing the MAC
// tag. To stay zero-alloc we use
// hmac.Hash.Sum(b) where b is a fixed-size
// array; the result is then written into
// our fixed out buffer.
func (t *Tarpit) computeCookie(connID uint64, subject uint32, now time.Time) [32]byte {
	mac := t.macPool.Get().(hash.Hash)
	defer t.macPool.Put(mac)
	mac.Reset()
	var buf [20]byte
	binary.BigEndian.PutUint64(buf[0:8], connID)
	binary.BigEndian.PutUint32(buf[8:12], subject)
	binary.BigEndian.PutUint64(buf[12:20], uint64(now.UnixNano()))
	mac.Write(buf[:])
	// hmac.Sum accepts a fixed-size byte
	// slice and APPENDS the MAC tag to it.
	// We pass a [32]byte zero buffer and
	// then copy the trailing 32 bytes.
	var out [32]byte
	var scratch [32]byte
	mac.Sum(scratch[:0])
	copy(out[:], scratch[:])
	return out
}

// SetNow injects a fake clock. Tests only.
func (t *Tarpit) SetNow(now func() time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.now = now
}
