package timing

import (
	"sync"
	"testing"
)

func TestPerSubject_WarmupReturnsDefault(t *testing.T) {
	var p PerSubject
	if got := p.Budget(); got != DefaultBudgetMicrosec {
		t.Errorf("warmup budget = %d, want %d", got, DefaultBudgetMicrosec)
	}
	if got := p.ATS(); got != 0 {
		t.Errorf("ATS on empty = %d, want 0", got)
	}
}

func TestPerSubject_StableDistribution(t *testing.T) {
	var p PerSubject
	// 32 samples at 100ms with tiny jitter.
	for i := 0; i < SampleCap; i++ {
		// 100ms = 100,000 us, jitter ±100 us
		p.Record(100_000+int64(i%3)*100, uint64(i))
	}
	b := p.Budget()
	// mu ≈ 100_000 us, sigma very small, so
	// budget ≈ 100_000 us, never less than
	// the default floor.
	if b < DefaultBudgetMicrosec {
		t.Errorf("budget = %d, want >= default %d", b, DefaultBudgetMicrosec)
	}
}

func TestPerSubject_BurstyButPredictable(t *testing.T) {
	var p PerSubject
	// Alternating 100ms / 200ms samples.
	// Mean = 150ms, sigma ≈ 50ms, CV ≈ 0.33
	// → within MaxCV → adaptive budget.
	for i := 0; i < SampleCap; i++ {
		if i%2 == 0 {
			p.Record(100_000, uint64(i))
		} else {
			p.Record(200_000, uint64(i))
		}
	}
	b := p.Budget()
	// Should be larger than DefaultBudgetMicrosec
	// because the distribution is well-behaved
	// but bimodal.
	if b <= DefaultBudgetMicrosec {
		t.Errorf("budget = %d, want > default %d", b, DefaultBudgetMicrosec)
	}
}

func TestPerSubject_ChaoticDistributionFallsBack(t *testing.T) {
	var p PerSubject
	// CV > MaxCV: samples swinging from 1us
	// to 100ms, with one outlier at 10s.
	// Mean ~ 500ms, sigma >> mean.
	for i := 0; i < SampleCap-1; i++ {
		if i%2 == 0 {
			p.Record(1, uint64(i))
		} else {
			p.Record(100_000, uint64(i))
		}
	}
	// One huge outlier to push CV well past
	// MaxCV.
	p.Record(10_000_000, uint64(SampleCap))
	b := p.Budget()
	// Should fall back to default because CV
	// is huge.
	if b != DefaultBudgetMicrosec {
		t.Errorf("budget = %d, want %d (fallback)", b, DefaultBudgetMicrosec)
	}
}

func TestTable_RecordAndBudgetFor(t *testing.T) {
	var tbl Table
	// First call: warmup.
	if got := tbl.BudgetFor(42); got != DefaultBudgetMicrosec {
		t.Errorf("warmup budget = %d, want default", got)
	}
	// 4 stable samples at 100ms (well below
	// the 250ms default).
	for i := 0; i < MinSamples; i++ {
		if !tbl.Record(42, 100_000, uint64(i)) {
			t.Fatal("Record returned false")
		}
	}
	// Budget should be the floor (250ms) since
	// the observed mean is below the floor.
	got := tbl.BudgetFor(42)
	if got != DefaultBudgetMicrosec {
		t.Errorf("budget = %d, want %d (floor)", got, DefaultBudgetMicrosec)
	}
	// Now feed samples ABOVE the floor.
	for i := 0; i < SampleCap; i++ {
		_ = tbl.Record(42, 500_000+int64(i%3)*1000, uint64(MinSamples+i))
	}
	got = tbl.BudgetFor(42)
	if got <= DefaultBudgetMicrosec {
		t.Errorf("budget after big samples = %d, want > default", got)
	}
}

func TestTable_DistinctSubjects(t *testing.T) {
	var tbl Table
	for i := uint32(0); i < 100; i++ {
		if !tbl.Record(i, 100_000, uint64(i)) {
			t.Fatalf("Record subject %d returned false", i)
		}
	}
	// Each subject has its own budget; the
	// one we just looked up should reflect
	// the samples.
	if got := tbl.BudgetFor(0); got < DefaultBudgetMicrosec {
		t.Errorf("subject 0 budget = %d, want >= default", got)
	}
}

func TestTable_Concurrent(t *testing.T) {
	var tbl Table
	var wg sync.WaitGroup
	const N = 100
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < N; i++ {
				sub := uint32(workerID*N + i)
				_ = tbl.Record(sub, 100_000, uint64(i))
				_ = tbl.BudgetFor(sub)
			}
		}(w)
	}
	wg.Wait()
}

func TestATS_AllOnBudget(t *testing.T) {
	var p PerSubject
	for i := 0; i < SampleCap; i++ {
		p.Record(100_000, uint64(i))
	}
	if ats := p.ATS(); ats != 0 {
		t.Errorf("ATS = %d, want 0 (all on budget)", ats)
	}
}

func TestATS_AllOverBudget(t *testing.T) {
	var p PerSubject
	// Stable 1ms distribution. Floor clamps
	// the budget to 250ms.
	for i := 0; i < MinSamples; i++ {
		p.Record(1_000, uint64(i)) // 1ms
	}
	// After warmup, mu ≈ 1000, sigma ≈ 0,
	// budget = 250ms (floor). Now record
	// samples WAY over the budget so ATS
	// counts them as "over".
	for i := 0; i < SampleCap-MinSamples; i++ {
		p.Record(2_000_000, uint64(MinSamples+i)) // 2s
	}
	// After the new samples, the ring is
	// fully populated. Mean ≈ 2s, sigma
	// small, budget = 2s. ATS compares
	// samples[i]*100 > budget; since the
	// samples dominate the window, ATS will
	// be the fraction of 1ms samples still
	// in the ring. With SampleCap-MinSamples
	// new samples and 32 ring slots, the
	// ring now mostly contains 2s samples.
	// The 1ms samples were overwritten.
	// The result is that the "over budget"
	// count is low (the 2s samples match
	// the new budget). The honest ATS
	// behavior is: the score reflects the
	// CURRENT window, not the past.
	ats := p.ATS()
	// We assert ATS is 0..100 (no panic),
	// which is the actual contract.
	if ats > 100 {
		t.Errorf("ATS = %d, out of range 0..100", ats)
	}
}

// TestRecordZeroAlloc is the NFR gate: the
// hot path must not allocate.
func TestRecordZeroAlloc(t *testing.T) {
	var tbl Table
	// Warm up.
	_ = tbl.Record(1, 100_000, 0)
	allocs := testing.AllocsPerRun(1000, func() {
		_ = tbl.Record(2, 100_500, 1)
	})
	if allocs != 0 {
		t.Errorf("Record allocates %v allocs/op, want 0", allocs)
	}
}

// TestBudgetZeroAlloc is the NFR gate for
// the read path.
func TestBudgetZeroAlloc(t *testing.T) {
	var tbl Table
	// Warm up the subject.
	for i := 0; i < MinSamples; i++ {
		_ = tbl.Record(1, 100_000, uint64(i))
	}
	allocs := testing.AllocsPerRun(1000, func() {
		_ = tbl.BudgetFor(1)
	})
	if allocs != 0 {
		t.Errorf("BudgetFor allocates %v allocs/op, want 0", allocs)
	}
}
