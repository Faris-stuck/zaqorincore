package mock

import (
	"sync"
	"time"
)

// CanaryEntry is the per-token state the
// production canary store keeps. The mock keeps
// the same shape so tests can assert on the
// same fields.
type CanaryEntry struct {
	Token      string
	CreatedAt  time.Time
	LastTouch  time.Time
	TouchCount int
	// Subject is the engine Subject (uint32 hash
	// of the source IP) that last touched this
	// token. Zero if never touched.
	Subject uint32
}

// CanaryStore is the interface the engine
// depends on for canary-token bookkeeping.
type CanaryStore interface {
	// Touch records that `subject` accessed the
	// token. Returns true if this is the FIRST
	// touch (L0 -> L1 candidate), false otherwise.
	Touch(token string, subject uint32) (firstTouch bool)
	// Lookup returns the entry for `token`. The
	// bool is false if the token is unknown.
	Lookup(token string) (*CanaryEntry, bool)
	// Register adds a new token to the store.
	// Idempotent: re-registering updates the
	// CreatedAt to now.
	Register(token string)
	// Len returns the number of registered tokens.
	Len() int
	// Reset clears all entries. Test helper.
	Reset()
}

// CanaryStoreMock is an in-memory implementation
// of CanaryStore, safe for concurrent use.
type CanaryStoreMock struct {
	mu      sync.Mutex
	entries map[string]*CanaryEntry
}

func NewCanaryStoreMock() *CanaryStoreMock {
	return &CanaryStoreMock{entries: make(map[string]*CanaryEntry)}
}

// Touch implements CanaryStore.
func (c *CanaryStoreMock) Touch(token string, subject uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[token]
	now := time.Now()
	if !ok {
		// Token not registered = unknown canary.
		// We still record the touch so the
		// operator can audit later.
		c.entries[token] = &CanaryEntry{
			Token: token, CreatedAt: now, LastTouch: now,
			TouchCount: 1, Subject: subject,
		}
		return true
	}
	e.LastTouch = now
	e.TouchCount++
	e.Subject = subject
	return e.TouchCount == 1
}

func (c *CanaryStoreMock) Lookup(token string) (*CanaryEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[token]
	if !ok {
		return nil, false
	}
	cp := *e
	return &cp, true
}

func (c *CanaryStoreMock) Register(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if e, ok := c.entries[token]; ok {
		e.CreatedAt = now
		return
	}
	c.entries[token] = &CanaryEntry{Token: token, CreatedAt: now}
}

func (c *CanaryStoreMock) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *CanaryStoreMock) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CanaryEntry)
}
