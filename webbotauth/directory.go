package webbotauth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DirectoryPath is the well-known path a crawler publishes its signing keys
// at. A Signature-Agent URL naming a host alone is read as this path under it.
const DirectoryPath = "/.well-known/http-message-signatures-directory"

// What a Directory holds to unless it sets its own limits.
const (
	// MaxDirectoryBytes is the largest body read.
	MaxDirectoryBytes = 64 << 10
	// MaxDirectoryKeys is the most keys one directory may publish.
	MaxDirectoryKeys = 32
	// DefaultDirectoryTTL is how long fetched keys are used before the
	// directory is asked again.
	DefaultDirectoryTTL = time.Hour
	// DefaultNegativeTTL is how long a failure is remembered when the response
	// asked for no other delay.
	DefaultNegativeTTL = 5 * time.Minute
	// DefaultDirectoryTimeout bounds one fetch.
	DefaultDirectoryTimeout = 10 * time.Second
)

// Kinds of Reason a directory fetch records.
const (
	// ReasonRefreshFailed reports a refresh that did not complete. The keys
	// already cached are kept: a failure evicts nothing.
	ReasonRefreshFailed = "key refresh failed"
	// ReasonUnusableKey reports a published key this package cannot verify
	// with. It is skipped and the rest of the document kept.
	ReasonUnusableKey = "unusable published key"
)

var (
	// ErrDirectoryStatus reports a key directory that answered anything but
	// 200, which is a discovery failure rather than a document to read.
	ErrDirectoryStatus = errors.New("a key directory fetch is a discovery failure unless it answers 200")
	// ErrDirectoryRedirect reports a redirect, which a key directory fetch
	// never follows: the deliberate inverse of the five hops robots.txt allows.
	ErrDirectoryRedirect = errors.New("a key directory fetch follows no redirect")
	// ErrDirectoryTooLarge reports a body above the bytes allowed.
	ErrDirectoryTooLarge = errors.New("the key directory body is above the size allowed")
	// ErrTooManyKeys reports a directory publishing more keys than allowed.
	ErrTooManyKeys = errors.New("the key directory publishes more keys than allowed")
	// ErrDirectoryBody reports a body that is not a JWK Set holding a key this
	// package can verify with.
	ErrDirectoryBody = errors.New("the key directory body is not a JWK Set this package can read")
	// ErrAddressNotAllowed reports a name that resolved into the network the
	// fetch is made from.
	ErrAddressNotAllowed = errors.New("a key directory must not resolve to a loopback, private, link-local or otherwise internal address")
	// ErrNoTransport reports a Directory with no RoundTripper to fetch through.
	ErrNoTransport = errors.New("a Directory fetches through a RoundTripper, which must be set")
)

// jwkSet is the document a key directory serves.
type jwkSet struct {
	Keys []JWK `json:"keys"`
}

// Keys is what a directory published, as of the fetch that filled the cache.
type Keys struct {
	Directory   string    // directory URL as the caller named it
	URL         string    // URL that was fetched, the well-known path included
	Thumbprints []string  // RFC 7638 thumbprints the keys are cached under
	FetchedAt   time.Time // when the cached document was read
	Reasons     []Reason
}

// Directory fetches and caches the keys a crawler publishes at DirectoryPath.
// Keys are cached by directory URL and thumbprint together, because a key
// proves nothing about a directory that did not publish it. A failed refresh
// keeps the keys already cached; a successful one revokes the keys it omits.
// Any status but 200 is a discovery failure and no redirect is ever followed.
type Directory struct {
	// Transport is what fetches are made through. Nothing here follows a
	// redirect, so a RoundTripper rather than a Client is all this needs.
	Transport http.RoundTripper
	// Timeout bounds one fetch, DefaultDirectoryTimeout when zero.
	Timeout time.Duration
	// TTL is how long fetched keys are used, DefaultDirectoryTTL when zero.
	TTL time.Duration
	// MaxBytes is the largest body read, MaxDirectoryBytes when zero.
	MaxBytes int64
	// MaxKeys is the most keys one directory may publish, MaxDirectoryKeys
	// when zero.
	MaxKeys int
	// NegativeTTL is how long a failure with no Retry-After is remembered,
	// DefaultNegativeTTL when zero.
	NegativeTTL time.Duration

	mu       sync.Mutex
	keys     map[keyIndex]ed25519.PublicKey
	states   map[string]*dirState
	inflight map[string]*fetchCall
}

// dirState is what is known about one directory: the keys last fetched from it
// and the failure, if any, the last refresh ended in.
type dirState struct {
	url         string
	thumbprints []string
	fetchedAt   time.Time
	reasons     []Reason
	err         error
	retryAt     time.Time
}

type fetchCall struct {
	done chan struct{}
	keys Keys
	err  error
}

// NewDirectory returns a Directory fetching through rt.
func NewDirectory(rt http.RoundTripper) *Directory {
	return &Directory{Transport: rt}
}

// Keys returns the keys the directory publishes, fetching them when the cache
// holds none or none still fresh as of now. Concurrent calls for one directory
// are coalesced into a single fetch and all of them read its result.
func (d *Directory) Keys(ctx context.Context, directory string, now time.Time) (Keys, error) {
	target, err := directoryURL(directory)
	if err != nil {
		return Keys{}, err
	}

	d.mu.Lock()
	d.init()
	if st := d.states[directory]; st != nil {
		if st.err == nil && len(st.thumbprints) > 0 && now.Sub(st.fetchedAt) < d.ttl() {
			out := st.snapshot(directory)
			d.mu.Unlock()
			return out, nil
		}
		if st.err != nil && now.Before(st.retryAt) {
			out, held := st.held(directory)
			d.mu.Unlock()
			return out, held
		}
	}
	call, leader := d.call(directory)
	d.mu.Unlock()

	if !leader {
		<-call.done
		return call.keys, call.err
	}
	keys, err := d.refresh(ctx, directory, target, now)
	d.mu.Lock()
	delete(d.inflight, directory)
	d.mu.Unlock()
	call.keys, call.err = keys, err
	close(call.done)
	return keys, err
}

// Lookup returns a cached key of a directory, by the thumbprint it is cached
// under.
func (d *Directory) Lookup(directory, thumbprint string) (ed25519.PublicKey, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	pub, ok := d.keys[keyIndex{directory, thumbprint}]
	return pub, ok
}

// Keyring returns a keyring holding the keys cached for the directories named,
// or for every directory cached when none is named, so Verify can be reached
// with keys that were fetched rather than keys written down.
func (d *Directory) Keyring(directories ...string) *Keyring {
	k := NewKeyring()
	d.mu.Lock()
	defer d.mu.Unlock()
	for index, pub := range d.keys {
		if len(directories) == 0 || slices.Contains(directories, index.directory) {
			k.keys[index] = pub
		}
	}
	return k
}

func (d *Directory) init() {
	if d.keys == nil {
		d.keys = make(map[keyIndex]ed25519.PublicKey)
	}
	if d.states == nil {
		d.states = make(map[string]*dirState)
	}
	if d.inflight == nil {
		d.inflight = make(map[string]*fetchCall)
	}
}

func (d *Directory) call(directory string) (*fetchCall, bool) {
	if c, ok := d.inflight[directory]; ok {
		return c, false
	}
	c := &fetchCall{done: make(chan struct{})}
	d.inflight[directory] = c
	return c, true
}

func (d *Directory) refresh(ctx context.Context, directory, target string, now time.Time) (Keys, error) {
	set, retryAfter, err := d.get(ctx, target, now)

	d.mu.Lock()
	defer d.mu.Unlock()
	d.init()

	var (
		thumbprints []string
		reasons     []Reason
	)
	if err == nil {
		thumbprints, reasons, err = d.record(directory, set)
	}
	if err != nil {
		st := d.states[directory]
		if st == nil {
			st = &dirState{}
			d.states[directory] = st
		}
		st.url = target
		st.err = err
		st.retryAt = now.Add(d.backoff(retryAfter))
		return st.held(directory)
	}
	st := &dirState{url: target, thumbprints: thumbprints, fetchedAt: now, reasons: reasons}
	d.states[directory] = st
	return st.snapshot(directory), nil
}

// record replaces every key cached for the directory with the ones it just
// published: a key the document omits is revoked by its absence.
func (d *Directory) record(directory string, set jwkSet) ([]string, []Reason, error) {
	if max := d.maxKeys(); len(set.Keys) > max {
		return nil, nil, fmt.Errorf("webbotauth: %s publishes %d keys, past the %d allowed: %w", directory, len(set.Keys), max, ErrTooManyKeys)
	}
	var (
		reasons     []Reason
		thumbprints []string
	)
	fresh := make(map[string]ed25519.PublicKey, len(set.Keys))
	for i, j := range set.Keys {
		pub, err := j.PublicKey()
		if err != nil {
			reasons = append(reasons, Reason{ReasonUnusableKey, fmt.Sprintf("key %d of %s is not one this package verifies with (%v): it is skipped and the rest of the document kept", i, directory, err)})
			continue
		}
		thumbprint, err := j.Thumbprint()
		if err != nil {
			reasons = append(reasons, Reason{ReasonUnusableKey, fmt.Sprintf("key %d of %s has no thumbprint (%v): it is skipped", i, directory, err)})
			continue
		}
		if j.KeyID != "" && j.KeyID != thumbprint {
			reasons = append(reasons, Reason{ReasonUnusableKey, fmt.Sprintf("%s published kid %q for a key whose thumbprint is %q: the key is skipped, a kid is not taken on its word", directory, j.KeyID, thumbprint)})
			continue
		}
		if _, seen := fresh[thumbprint]; seen {
			continue
		}
		fresh[thumbprint] = pub
		thumbprints = append(thumbprints, thumbprint)
	}
	if len(fresh) == 0 {
		return nil, nil, fmt.Errorf("webbotauth: %s published no key this package can verify with: %w", directory, ErrDirectoryBody)
	}
	for index := range d.keys {
		if index.directory == directory {
			delete(d.keys, index)
		}
	}
	for thumbprint, pub := range fresh {
		d.keys[keyIndex{directory, thumbprint}] = pub
	}
	slices.Sort(thumbprints)
	return thumbprints, reasons, nil
}

func (d *Directory) get(ctx context.Context, target string, now time.Time) (jwkSet, time.Duration, error) {
	if d.Transport == nil {
		return jwkSet{}, 0, fmt.Errorf("webbotauth: %s: %w", target, ErrNoTransport)
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return jwkSet{}, 0, fmt.Errorf("webbotauth: %s: %w", target, err)
	}
	req.Header.Set("Accept", "application/http-message-signatures-directory+json, application/jwk-set+json")

	resp, err := d.Transport.RoundTrip(req)
	if err != nil {
		return jwkSet{}, 0, fmt.Errorf("webbotauth: fetching %s: %w", target, err)
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 == 3 {
		return jwkSet{}, retryAfter(resp, now), fmt.Errorf("webbotauth: %s answered %d to %q, which is not followed: %w", target, resp.StatusCode, resp.Header.Get("Location"), ErrDirectoryRedirect)
	}
	if resp.StatusCode != http.StatusOK {
		return jwkSet{}, retryAfter(resp, now), fmt.Errorf("webbotauth: %s answered %d: %w", target, resp.StatusCode, ErrDirectoryStatus)
	}

	max := d.maxBytes()
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return jwkSet{}, 0, fmt.Errorf("webbotauth: reading %s: %w", target, err)
	}
	if int64(len(body)) > max {
		return jwkSet{}, 0, fmt.Errorf("webbotauth: %s answered more than the %d bytes read: %w", target, max, ErrDirectoryTooLarge)
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return jwkSet{}, 0, fmt.Errorf("webbotauth: %s: %v: %w", target, err, ErrDirectoryBody)
	}
	return set, 0, nil
}

// backoff is how long a failure is remembered: the Retry-After the response
// gave, honoured as the server spelled it, and NegativeTTL when it gave none.
func (d *Directory) backoff(retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return retryAfter
	}
	return d.negativeTTL()
}

func (d *Directory) ttl() time.Duration {
	if d.TTL > 0 {
		return d.TTL
	}
	return DefaultDirectoryTTL
}

func (d *Directory) negativeTTL() time.Duration {
	if d.NegativeTTL > 0 {
		return d.NegativeTTL
	}
	return DefaultNegativeTTL
}

func (d *Directory) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return DefaultDirectoryTimeout
}

func (d *Directory) maxBytes() int64 {
	if d.MaxBytes > 0 {
		return d.MaxBytes
	}
	return MaxDirectoryBytes
}

func (d *Directory) maxKeys() int {
	if d.MaxKeys > 0 {
		return d.MaxKeys
	}
	return MaxDirectoryKeys
}

func (s *dirState) snapshot(directory string) Keys {
	return Keys{
		Directory:   directory,
		URL:         s.url,
		Thumbprints: slices.Clone(s.thumbprints),
		FetchedAt:   s.fetchedAt,
		Reasons:     slices.Clone(s.reasons),
	}
}

// held is what a directory whose refresh failed answers with: the keys already
// cached, which no failure evicts, or the failure itself when there are none.
func (s *dirState) held(directory string) (Keys, error) {
	if len(s.thumbprints) == 0 {
		return Keys{}, s.err
	}
	out := s.snapshot(directory)
	out.Reasons = append(out.Reasons, Reason{ReasonRefreshFailed, fmt.Sprintf(
		"refreshing %s failed (%v): the %d keys fetched %s are kept, and nothing is fetched again before %s",
		s.url, s.err, len(s.thumbprints), s.fetchedAt.Format(time.RFC3339), s.retryAt.Format(time.RFC3339))})
	return out, nil
}

// directoryURL reads a Signature-Agent URL as the URL to fetch: https only,
// and the well-known path when the URL names a host alone, which the legacy
// bare string form does.
func directoryURL(raw string) (string, error) {
	if err := checkHTTPS(raw); err != nil {
		return "", fmt.Errorf("webbotauth: key directory %q: %w", raw, err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("webbotauth: key directory %q: %v: %w", raw, err, ErrNotHTTPS)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = DirectoryPath
	}
	u.Fragment = ""
	return u.String(), nil
}

func retryAfter(resp *http.Response, now time.Time) time.Duration {
	value := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	base := now
	if date, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		base = date
	}
	if d := when.Sub(base); d > 0 {
		return d
	}
	return 0
}

// sharedAddressSpace is the carrier-grade NAT range, which netip does not
// report as private.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// AllowedAddress is the address policy a key directory fetch dials under: a
// directory published on the public internet never resolves into the network
// doing the fetching, so an address that does is refused rather than dialed.
func AllowedAddress(addr netip.Addr) error {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return fmt.Errorf("webbotauth: %q is not an IP address: %w", addr, ErrAddressNotAllowed)
	}
	for _, c := range []struct {
		refuse bool
		what   string
	}{
		{addr.IsLoopback(), "loopback"},
		{addr.IsUnspecified(), "unspecified"},
		{addr.IsLinkLocalUnicast(), "link-local"},
		{addr.IsLinkLocalMulticast(), "link-local multicast"},
		{addr.IsInterfaceLocalMulticast(), "interface-local multicast"},
		{addr.IsMulticast(), "multicast"},
		{addr.IsPrivate(), "private"},
		{sharedAddressSpace.Contains(addr), "carrier-grade NAT"},
	} {
		if c.refuse {
			return fmt.Errorf("webbotauth: %s is a %s address: %w", addr, c.what, ErrAddressNotAllowed)
		}
	}
	return nil
}

// Resolver resolves a host name to the addresses a dial would use.
// *net.Resolver satisfies it, and a test supplies its own.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer dials a key directory only after the name has been resolved here and
// the address it resolved to has passed the policy, so neither a DNS record
// nor a URL can point a fetch at the network it is made from.
type Dialer struct {
	// Resolver resolves names, net.DefaultResolver when nil.
	Resolver Resolver
	// Policy decides one resolved address, AllowedAddress when nil.
	Policy func(netip.Addr) error
	// Dial opens the connection to an address the policy allowed, a zero
	// net.Dialer when nil.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// DialContext satisfies the DialContext field of http.Transport.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("webbotauth: dialing %q: %w", address, err)
	}
	addrs, err := d.addresses(ctx, network, host)
	if err != nil {
		return nil, err
	}
	policy := d.Policy
	if policy == nil {
		policy = AllowedAddress
	}
	var refused []error
	for _, addr := range addrs {
		addr = addr.Unmap()
		if err := policy(addr); err != nil {
			refused = append(refused, err)
			continue
		}
		conn, err := d.dial(ctx, network, net.JoinHostPort(addr.String(), port))
		if err != nil {
			refused = append(refused, err)
			continue
		}
		return conn, nil
	}
	if len(refused) == 0 {
		return nil, fmt.Errorf("webbotauth: %q resolves to no address: %w", host, ErrAddressNotAllowed)
	}
	return nil, fmt.Errorf("webbotauth: %q: %w", host, errors.Join(refused...))
}

func (d *Dialer) addresses(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	r := d.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupNetIP(ctx, lookupNetwork(network), host)
	if err != nil {
		return nil, fmt.Errorf("webbotauth: resolving %q: %w", host, err)
	}
	return addrs, nil
}

func (d *Dialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if d.Dial != nil {
		return d.Dial(ctx, network, address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

func lookupNetwork(network string) string {
	switch network {
	case "tcp4", "udp4", "ip4":
		return "ip4"
	case "tcp6", "udp6", "ip6":
		return "ip6"
	}
	return "ip"
}
