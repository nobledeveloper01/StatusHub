package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/adapters"
	"github.com/nobledeveloper01/StatusHub/internal/adapters/paystack"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/ratelimit"
	"github.com/nobledeveloper01/StatusHub/internal/receive"
)

func TestRateLimiterSmoothsBurstsRatherThanBlockingThem(t *testing.T) {
	// A fixed window would let a tenant spend a whole minute's allowance in
	// the first second and then take the service down for the other
	// fifty-nine. A bucket permits a genuine burst — which providers really
	// do produce after their own outages — and then holds the sustained rate.
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	l := ratelimit.New(ratelimit.Options{PerSecond: 10, Burst: 30, Now: clock.now})

	for i := 0; i < 30; i++ {
		if d := l.Allow("tenant"); !d.Allowed {
			t.Fatalf("request %d in the burst was refused; the bucket holds 30", i+1)
		}
	}
	d := l.Allow("tenant")
	if d.Allowed {
		t.Fatal("the 31st request was allowed with an empty bucket")
	}

	// A 429 without a Retry-After leaves the caller guessing, and most
	// providers guess badly.
	if d.RetryAfter <= 0 {
		t.Fatal("a refusal carried no Retry-After")
	}
	if d.Header() == "0" {
		t.Error("Retry-After of 0 tells the caller to retry immediately, which is never what a refusal means")
	}

	// Waiting the stated time succeeds, which is the property that makes
	// Retry-After worth honouring.
	clock.advance(d.RetryAfter + time.Millisecond)
	if !l.Allow("tenant").Allowed {
		t.Fatal("a caller that honoured Retry-After was refused again")
	}
}

func TestRateLimiterIsPerTenant(t *testing.T) {
	// One tenant's runaway integration must not throttle anyone else.
	clock := &testClock{t: time.Now().UTC()}
	l := ratelimit.New(ratelimit.Options{PerSecond: 1, Burst: 2, Now: clock.now})

	for i := 0; i < 2; i++ {
		l.Allow("noisy")
	}
	if l.Allow("noisy").Allowed {
		t.Fatal("the noisy tenant is not being limited")
	}
	if !l.Allow("quiet").Allowed {
		t.Fatal("a quiet tenant was refused because of another tenant's traffic")
	}
}

func TestRateLimiterForgetsIdleTenants(t *testing.T) {
	// Otherwise the map grows with every tenant that has ever sent a webhook:
	// a slow memory leak keyed on customer count.
	clock := &testClock{t: time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)}
	l := ratelimit.New(ratelimit.Options{PerSecond: 10, Burst: 10, IdleAfter: time.Minute, Now: clock.now})

	for i := 0; i < 50; i++ {
		l.Allow("tenant-" + strconv.Itoa(i))
	}
	if l.Tracked() != 50 {
		t.Fatalf("tracking %d buckets, want 50", l.Tracked())
	}

	clock.advance(2 * time.Minute)
	l.Allow("tenant-0") // still active
	if removed := l.Sweep(); removed != 49 {
		t.Errorf("swept %d idle buckets, want 49", removed)
	}
	if l.Tracked() != 1 {
		t.Errorf("tracking %d after the sweep, want 1", l.Tracked())
	}
}

func TestBoundedSemaphoreRefusesRatherThanBlocks(t *testing.T) {
	// Blocking would convert a capacity problem into a latency problem, and
	// the receiver's whole design is that it answers fast or says no.
	b := ratelimit.NewBounded("test", 2)
	// Two separate acquisitions, written out rather than combined: each call
	// has a side effect, and `a() || a()` reads as a redundant expression to
	// anybody — including a linter — who does not know that.
	for i := 0; i < 2; i++ {
		if !b.TryAcquire() {
			t.Fatalf("could not take slot %d of 2", i+1)
		}
	}

	done := make(chan bool, 1)
	go func() { done <- b.TryAcquire() }()
	select {
	case got := <-done:
		if got {
			t.Fatal("the semaphore allowed a third holder")
		}
	case <-time.After(time.Second):
		t.Fatal("TryAcquire blocked; it must refuse instead")
	}

	b.Release()
	if !b.TryAcquire() {
		t.Fatal("a released slot was not reusable")
	}
	if b.InUse() != 2 || b.Capacity() != 2 {
		t.Errorf("in use %d of %d", b.InUse(), b.Capacity())
	}
}

func TestBoundedSemaphoreSurvivesAnOverRelease(t *testing.T) {
	// An over-release is a bug in the caller. Panicking would take a process
	// down over a leak; the ceiling stays honest instead, and the in-use
	// gauge makes the leak visible.
	b := ratelimit.NewBounded("test", 1)
	b.Release()
	b.Release()
	if !b.TryAcquire() {
		t.Fatal("the semaphore was corrupted by an over-release")
	}
	if b.TryAcquire() {
		t.Fatal("the ceiling was raised by an over-release")
	}
}

func TestReceiverRefusesWithRetryAfterRatherThanQueueing(t *testing.T) {
	ctx := context.Background()
	s := memStore(t)

	ep := domain.Endpoint{
		ID: domain.NewID(domain.PrefixEndpoint), TenantID: tenantA, Provider: "paystack",
		Environment: domain.EnvLive, ReceiverToken: domain.NewToken(),
		SecretRef: testSecretRef, AdapterName: "paystack", Enabled: true,
	}
	mustNoErr(t, s.CreateEndpoint(ctx, ep), "creating the endpoint")

	r := receive.New(receive.Options{
		Store: s, Registry: adapters.New(), Secrets: staticSecrets(testSecretRef, paystackSecret),
		// Deliberately tiny, so the refusal is reachable in a test. The
		// shipped default is 2,000/sec with a 10,000 burst per tenant.
		PerTenantPerSecond: 1, Burst: 3,
	})
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	body := fixture(t, "paystack", "charge.success.json")
	sig := paystackSign(body, paystackSecret)

	post := func() *http.Response {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			srv.URL+ep.ReceiverPath(slugA), strings.NewReader(string(body)))
		mustNoErr(t, err, "building")
		req.Header.Set(paystack.Header, sig)
		resp, err := srv.Client().Do(req)
		mustNoErr(t, err, "sending")
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	for i := 0; i < 3; i++ {
		if got := post().StatusCode; got != http.StatusOK {
			t.Fatalf("request %d = %d, want 200 within the burst", i+1, got)
		}
	}

	resp := post()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status past the burst = %d, want 429", resp.StatusCode)
	}
	// The header is what makes this backpressure rather than a failure.
	after := resp.Header.Get("Retry-After")
	if after == "" {
		t.Fatal("the 429 carried no Retry-After; the provider is left guessing")
	}
	if n, err := strconv.Atoi(after); err != nil || n < 1 {
		t.Errorf("Retry-After = %q, want at least 1 second", after)
	}

	// And nothing was stored for the refused request: a 429 must not
	// half-accept an event.
	events, err := s.ListUnnormalised(ctx, 100)
	mustNoErr(t, err, "listing")
	if len(events) != 3 {
		t.Errorf("%d events stored, want the 3 that were accepted", len(events))
	}
}

func TestRateLimiterIsSafeUnderConcurrency(t *testing.T) {
	// The receiver is the most concurrent thing in the system; a limiter with
	// a data race would be worse than no limiter.
	l := ratelimit.New(ratelimit.Options{PerSecond: 1_000_000, Burst: 1_000_000})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				l.Allow("tenant-" + strconv.Itoa(n%4))
			}
		}(i)
	}
	wg.Wait()
	if l.Tracked() != 4 {
		t.Errorf("tracking %d tenants, want 4", l.Tracked())
	}
}
