package webbotauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}

func jwkSetBody(t *testing.T, keys ...JWK) string {
	t.Helper()
	body, err := json.Marshal(jwkSet{Keys: keys})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(body)
}

func thumbprintOf(t *testing.T, j JWK) string {
	t.Helper()
	thumbprint, err := j.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return thumbprint
}

// serve answers every request the same way and counts the requests it was
// asked for, so a test can pin that nothing was fetched twice.
func serve(status int, body string, header http.Header, count *atomic.Int64, urls *[]string) roundTripFunc {
	var mu sync.Mutex
	return func(r *http.Request) (*http.Response, error) {
		count.Add(1)
		if urls != nil {
			mu.Lock()
			*urls = append(*urls, r.URL.String())
			mu.Unlock()
		}
		return response(status, body, header.Clone()), nil
	}
}

func TestDirectoryFetchesTheWellKnownPath(t *testing.T) {
	k := newKey(t)
	var count atomic.Int64
	var urls []string
	d := NewDirectory(serve(http.StatusOK, jwkSetBody(t, k.jwk), nil, &count, &urls))

	keys, err := d.Keys(context.Background(), "https://crawler.example", testNow)
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(urls) != 1 || urls[0] != testDirectory {
		t.Errorf("fetched %v, want %q: a URL naming a host alone is read as the well-known path under it", urls, testDirectory)
	}
	thumbprint := thumbprintOf(t, k.jwk)
	if len(keys.Thumbprints) != 1 || keys.Thumbprints[0] != thumbprint {
		t.Errorf("thumbprints = %v, want [%s]", keys.Thumbprints, thumbprint)
	}
	if !keys.FetchedAt.Equal(testNow) || keys.URL != testDirectory {
		t.Errorf("keys = %+v, want the URL fetched and the time it was fetched at", keys)
	}
	if _, ok := d.Lookup("https://crawler.example", thumbprint); !ok {
		t.Error("Lookup found no key under the thumbprint it was cached with")
	}
	if _, ok := d.Lookup("https://elsewhere.example", thumbprint); ok {
		t.Error("Lookup found the key under a directory that did not publish it")
	}
	if _, ok := d.Keyring().Lookup("https://crawler.example", thumbprint); !ok {
		t.Error("the keyring holds no key the fetch cached")
	}

	if _, err := d.Keys(context.Background(), "https://crawler.example", testNow.Add(time.Minute)); err != nil {
		t.Fatalf("second Keys: %v", err)
	}
	if count.Load() != 1 {
		t.Errorf("fetches = %d, want 1: keys still fresh are not fetched again", count.Load())
	}
}

func TestDirectoryRefusesEveryStatusButOKAndFollowsNoRedirect(t *testing.T) {
	body := jwkSetBody(t, newKey(t).jwk)
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusCreated, ErrDirectoryStatus},
		{http.StatusNoContent, ErrDirectoryStatus},
		{http.StatusMovedPermanently, ErrDirectoryRedirect},
		{http.StatusFound, ErrDirectoryRedirect},
		{http.StatusSeeOther, ErrDirectoryRedirect},
		{http.StatusTemporaryRedirect, ErrDirectoryRedirect},
		{http.StatusPermanentRedirect, ErrDirectoryRedirect},
		{http.StatusNotFound, ErrDirectoryStatus},
		{http.StatusInternalServerError, ErrDirectoryStatus},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("status %d", c.status), func(t *testing.T) {
			var count atomic.Int64
			var urls []string
			header := http.Header{"Location": []string{"https://elsewhere.example/keys"}}
			d := NewDirectory(serve(c.status, body, header, &count, &urls))

			if _, err := d.Keys(context.Background(), testDirectory, testNow); !errors.Is(err, c.want) {
				t.Errorf("error = %v, want it to be %v", err, c.want)
			}
			if count.Load() != 1 || len(urls) != 1 || urls[0] != testDirectory {
				t.Errorf("fetched %v, want %q once: a key directory fetch follows no hop", urls, testDirectory)
			}
		})
	}
}

func TestDirectoryFailedRefreshKeepsTheKeys(t *testing.T) {
	k := newKey(t)
	thumbprint := thumbprintOf(t, k.jwk)
	body := jwkSetBody(t, k.jwk)
	var fail atomic.Bool
	d := NewDirectory(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if fail.Load() {
			return nil, errors.New("the connection was refused")
		}
		return response(http.StatusOK, body, nil), nil
	}))

	if _, err := d.Keys(context.Background(), testDirectory, testNow); err != nil {
		t.Fatalf("Keys: %v", err)
	}
	fail.Store(true)

	keys, err := d.Keys(context.Background(), testDirectory, testNow.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("Keys after a failed refresh: %v, want the cached keys kept", err)
	}
	if len(keys.Thumbprints) != 1 || keys.Thumbprints[0] != thumbprint {
		t.Errorf("thumbprints = %v, want [%s]: a failed refresh evicts nothing", keys.Thumbprints, thumbprint)
	}
	if !hasReason(keys.Reasons, ReasonRefreshFailed) {
		t.Errorf("reasons = %v, want a %q reason", reasonKinds(keys.Reasons), ReasonRefreshFailed)
	}
	if !keys.FetchedAt.Equal(testNow) {
		t.Errorf("fetched at %s, want %s: the kept keys carry the fetch that read them", keys.FetchedAt, testNow)
	}
	if _, ok := d.Lookup(testDirectory, thumbprint); !ok {
		t.Error("Lookup found no key after a failed refresh, want the cached one kept")
	}
}

func TestDirectoryRefreshRevokesAnOmittedKey(t *testing.T) {
	gone, kept := newKey(t), newKey(t)
	first := jwkSetBody(t, gone.jwk, kept.jwk)
	second := jwkSetBody(t, kept.jwk)
	var refreshed atomic.Bool
	d := NewDirectory(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if refreshed.Load() {
			return response(http.StatusOK, second, nil), nil
		}
		return response(http.StatusOK, first, nil), nil
	}))

	if _, err := d.Keys(context.Background(), testDirectory, testNow); err != nil {
		t.Fatalf("Keys: %v", err)
	}
	refreshed.Store(true)
	keys, err := d.Keys(context.Background(), testDirectory, testNow.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("Keys after the refresh: %v", err)
	}
	if len(keys.Thumbprints) != 1 || keys.Thumbprints[0] != thumbprintOf(t, kept.jwk) {
		t.Errorf("thumbprints = %v, want only the key the document still publishes", keys.Thumbprints)
	}
	if _, ok := d.Lookup(testDirectory, thumbprintOf(t, gone.jwk)); ok {
		t.Error("the key the refreshed document omits is still cached, want it revoked by its absence")
	}
}

func TestDirectoryNegativeResultsLiveFiveMinutes(t *testing.T) {
	var count atomic.Int64
	d := NewDirectory(serve(http.StatusInternalServerError, "", nil, &count, nil))

	if _, err := d.Keys(context.Background(), testDirectory, testNow); !errors.Is(err, ErrDirectoryStatus) {
		t.Fatalf("error = %v, want %v", err, ErrDirectoryStatus)
	}
	if _, err := d.Keys(context.Background(), testDirectory, testNow.Add(4*time.Minute)); !errors.Is(err, ErrDirectoryStatus) {
		t.Errorf("error = %v, want the remembered %v", err, ErrDirectoryStatus)
	}
	if count.Load() != 1 {
		t.Errorf("fetches = %d, want 1 inside the %v a negative result lives", count.Load(), DefaultNegativeTTL)
	}
	if _, err := d.Keys(context.Background(), testDirectory, testNow.Add(DefaultNegativeTTL+time.Second)); !errors.Is(err, ErrDirectoryStatus) {
		t.Errorf("error = %v, want %v", err, ErrDirectoryStatus)
	}
	if count.Load() != 2 {
		t.Errorf("fetches = %d, want 2: past %v the directory is asked again", count.Load(), DefaultNegativeTTL)
	}
}

func TestDirectoryHonoursRetryAfter(t *testing.T) {
	cases := []struct {
		name  string
		value string
		wait  time.Duration
	}{
		{"seconds", "1200", 20 * time.Minute},
		{"an HTTP date", testNow.Add(20 * time.Minute).UTC().Format(http.TimeFormat), 20 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var count atomic.Int64
			header := http.Header{
				"Retry-After": []string{c.value},
				"Date":        []string{testNow.UTC().Format(http.TimeFormat)},
			}
			d := NewDirectory(serve(http.StatusServiceUnavailable, "", header, &count, nil))

			if _, err := d.Keys(context.Background(), testDirectory, testNow); !errors.Is(err, ErrDirectoryStatus) {
				t.Fatalf("error = %v, want %v", err, ErrDirectoryStatus)
			}
			if _, err := d.Keys(context.Background(), testDirectory, testNow.Add(c.wait-time.Minute)); err == nil {
				t.Error("Keys = no error, want the remembered refusal")
			}
			if count.Load() != 1 {
				t.Errorf("fetches = %d, want 1 before the %v the server asked for", count.Load(), c.wait)
			}
			if _, err := d.Keys(context.Background(), testDirectory, testNow.Add(c.wait+time.Second)); err == nil {
				t.Error("Keys = no error, want the refusal of the fetch made past the delay")
			}
			if count.Load() != 2 {
				t.Errorf("fetches = %d, want 2: past the delay the directory is asked again", count.Load())
			}
		})
	}
}

func TestDirectoryRefusesABodyAboveTheLimit(t *testing.T) {
	var count atomic.Int64
	d := NewDirectory(serve(http.StatusOK, strings.Repeat("a", MaxDirectoryBytes+1), nil, &count, nil))
	if _, err := d.Keys(context.Background(), testDirectory, testNow); !errors.Is(err, ErrDirectoryTooLarge) {
		t.Errorf("error = %v, want %v past the %d bytes read", err, ErrDirectoryTooLarge, MaxDirectoryBytes)
	}
}

func TestDirectoryRefusesTooManyKeys(t *testing.T) {
	published := make([]JWK, 0, MaxDirectoryKeys+1)
	for i := 0; i <= MaxDirectoryKeys; i++ {
		published = append(published, newKey(t).jwk)
	}
	body := jwkSetBody(t, published...)
	d := NewDirectory(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return response(http.StatusOK, body, nil), nil
	}))
	if _, err := d.Keys(context.Background(), testDirectory, testNow); !errors.Is(err, ErrTooManyKeys) {
		t.Errorf("error = %v, want %v past the %d keys allowed", err, ErrTooManyKeys, MaxDirectoryKeys)
	}
	if _, ok := d.Lookup(testDirectory, thumbprintOf(t, published[0])); ok {
		t.Error("a refused document cached a key")
	}
}

func TestDirectorySkipsAnUnusableKey(t *testing.T) {
	good := newKey(t)
	bad := JWK{Kty: "oct", Crv: "Ed25519", X: newKey(t).jwk.X}
	d := NewDirectory(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return response(http.StatusOK, jwkSetBody(t, bad, good.jwk), nil), nil
	}))
	keys, err := d.Keys(context.Background(), testDirectory, testNow)
	if err != nil {
		t.Fatalf("Keys: %v, want the usable key kept", err)
	}
	if len(keys.Thumbprints) != 1 || keys.Thumbprints[0] != thumbprintOf(t, good.jwk) {
		t.Errorf("thumbprints = %v, want only the key this package verifies with", keys.Thumbprints)
	}
	if !hasReason(keys.Reasons, ReasonUnusableKey) {
		t.Errorf("reasons = %v, want a %q reason", reasonKinds(keys.Reasons), ReasonUnusableKey)
	}

	onlyBad := NewDirectory(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return response(http.StatusOK, jwkSetBody(t, bad), nil), nil
	}))
	if _, err := onlyBad.Keys(context.Background(), testDirectory, testNow); !errors.Is(err, ErrDirectoryBody) {
		t.Errorf("error = %v, want %v for a document with no usable key", err, ErrDirectoryBody)
	}
}

func TestDirectoryCoalescesConcurrentFetches(t *testing.T) {
	k := newKey(t)
	body := jwkSetBody(t, k.jwk)
	release := make(chan struct{})
	var count atomic.Int64
	d := NewDirectory(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		count.Add(1)
		<-release
		return response(http.StatusOK, body, nil), nil
	}))

	var wg sync.WaitGroup
	got := make([]Keys, 8)
	errs := make([]error, len(got))
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = d.Keys(context.Background(), testDirectory, testNow)
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if count.Load() != 1 {
		t.Errorf("fetches = %d, want 1: concurrent fetches of one directory are coalesced", count.Load())
	}
	thumbprint := thumbprintOf(t, k.jwk)
	for i := range got {
		if errs[i] != nil {
			t.Fatalf("Keys from caller %d: %v", i, errs[i])
		}
		if len(got[i].Thumbprints) != 1 || got[i].Thumbprints[0] != thumbprint {
			t.Errorf("caller %d read %v, want [%s]: every caller reads the one fetch", i, got[i].Thumbprints, thumbprint)
		}
	}
}

func TestDirectoryFetchCarriesADeadline(t *testing.T) {
	var (
		deadline time.Time
		ok       bool
	)
	d := &Directory{Timeout: 2 * time.Second, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok = r.Context().Deadline()
		return response(http.StatusOK, jwkSetBody(t, newKey(t).jwk), nil), nil
	})}
	if _, err := d.Keys(context.Background(), testDirectory, testNow); err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if !ok {
		t.Fatal("the fetch carried no deadline, want every fetch bounded by Timeout")
	}
	if left := time.Until(deadline); left <= 0 || left > 2*time.Second {
		t.Errorf("deadline is %v away, want it inside the %v allowed", left, 2*time.Second)
	}
}

func TestDirectoryRefusesAPlainHTTPDirectory(t *testing.T) {
	d := NewDirectory(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Error("a plain http directory was fetched, want it refused before the request")
		return response(http.StatusOK, "{}", nil), nil
	}))
	if _, err := d.Keys(context.Background(), "http://crawler.example/directory", testNow); !errors.Is(err, ErrNotHTTPS) {
		t.Errorf("error = %v, want %v", err, ErrNotHTTPS)
	}
}

func TestAllowedAddress(t *testing.T) {
	cases := []struct {
		addr  string
		allow bool
	}{
		{"127.0.0.1", false},
		{"::1", false},
		{"0.0.0.0", false},
		{"10.1.2.3", false},
		{"172.16.4.5", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false},
		{"fe80::1", false},
		{"fc00::1", false},
		{"ff02::1", false},
		{"100.64.0.1", false},
		{"::ffff:127.0.0.1", false},
		{"203.0.113.7", true},
		{"2606:4700::1111", true},
	}
	for _, c := range cases {
		err := AllowedAddress(netip.MustParseAddr(c.addr))
		if c.allow && err != nil {
			t.Errorf("AllowedAddress(%s) = %v, want it dialed", c.addr, err)
		}
		if !c.allow && !errors.Is(err, ErrAddressNotAllowed) {
			t.Errorf("AllowedAddress(%s) = %v, want %v", c.addr, err, ErrAddressNotAllowed)
		}
	}
}

type testResolver map[string][]netip.Addr

func (r testResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	addrs, ok := r[host]
	if !ok {
		return nil, fmt.Errorf("no record for %q", host)
	}
	return addrs, nil
}

func TestDialerChecksAddressesAfterResolution(t *testing.T) {
	var dialed []string
	d := &Dialer{
		Resolver: testResolver{
			"crawler.example": {netip.MustParseAddr("127.0.0.1")},
			"keys.example":    {netip.MustParseAddr("203.0.113.7")},
		},
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			return nil, nil
		},
	}

	if _, err := d.DialContext(context.Background(), "tcp", "crawler.example:443"); !errors.Is(err, ErrAddressNotAllowed) {
		t.Errorf("error = %v, want %v: the name resolved inside the network doing the fetch", err, ErrAddressNotAllowed)
	}
	if len(dialed) != 0 {
		t.Errorf("dialed %v, want nothing: the address is checked after resolution and before the dial", dialed)
	}

	if _, err := d.DialContext(context.Background(), "tcp", "keys.example:443"); err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if len(dialed) != 1 || dialed[0] != "203.0.113.7:443" {
		t.Errorf("dialed %v, want the resolved address 203.0.113.7:443", dialed)
	}

	// A test supplies its own policy, so a test can dial an address the
	// published one refuses without reaching for the network.
	dialed = nil
	d.Policy = func(netip.Addr) error { return nil }
	if _, err := d.DialContext(context.Background(), "tcp", "crawler.example:443"); err != nil {
		t.Fatalf("DialContext under a test policy: %v", err)
	}
	if len(dialed) != 1 || dialed[0] != "127.0.0.1:443" {
		t.Errorf("dialed %v, want 127.0.0.1:443: the policy the Dialer carries decides", dialed)
	}

	if _, err := d.DialContext(context.Background(), "tcp", "unknown.example:443"); err == nil {
		t.Error("DialContext = no error for a name that resolves to nothing")
	}
}
