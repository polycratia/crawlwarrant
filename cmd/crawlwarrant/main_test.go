package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/polycratia/crawlwarrant/lint"
	"github.com/polycratia/crawlwarrant/webbotauth"
)

const cleanRobots = "User-agent: *\nDisallow: /private\n"

const citationRobots = "User-agent: Claude-SearchBot\nDisallow: /\n"

func allowAll(netip.Addr) error { return nil }

// resolver answers the names a test publishes and nothing else.
type resolver map[string][]netip.Addr

func (r resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if addrs, ok := r[host]; ok {
		return addrs, nil
	}
	return nil, fmt.Errorf("no record for %q", host)
}

func fixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "robots.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	return path
}

func exec(t *testing.T, c command, args ...string) (int, string, error) {
	t.Helper()
	var out bytes.Buffer
	c.out = &out
	code, err := c.run(args)
	return code, out.String(), err
}

// hopServer answers /0 with a chain of the given number of redirects and the
// clean file at the end of it.
func hopServer(t *testing.T, hops int) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			http.Error(w, "not a hop", http.StatusNotFound)
			return
		}
		if n < hops {
			http.Redirect(w, r, fmt.Sprintf("%s/%d", srv.URL, n+1), http.StatusFound)
			return
		}
		fmt.Fprint(w, cleanRobots)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLintAFileWithNothingToReport(t *testing.T) {
	code, out, err := exec(t, command{}, "lint", fixture(t, cleanRobots))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != exitOK || out != "no findings\n" {
		t.Errorf("run = (%d, %q), want (%d, %q)", code, out, exitOK, "no findings\n")
	}
}

func TestLintNamesTheTokenTheLineAndTheWording(t *testing.T) {
	path := fixture(t, citationRobots)

	code, out, err := exec(t, command{}, "lint", "-citation", path)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != exitErrors {
		t.Errorf("exit code = %d, want %d: the file holds an error", code, exitErrors)
	}
	for _, want := range []string{
		"error citation-wanted-search-disallowed Claude-SearchBot",
		"on line 2",
		"Anthropic:",
		"https://support.anthropic.com",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output = %q, want it to carry %q", out, want)
		}
	}

	code, out, err = exec(t, command{}, "lint", path)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != exitOK {
		t.Errorf("exit code = %d, want %d: nothing asked to be cited, so this file holds warnings only", code, exitOK)
	}
	if strings.Contains(out, "error ") {
		t.Errorf("output = %q, want no error without -citation", out)
	}
}

func TestLintJSON(t *testing.T) {
	code, out, err := exec(t, command{}, "lint", "-citation", "-json", fixture(t, citationRobots))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != exitErrors {
		t.Errorf("exit code = %d, want %d", code, exitErrors)
	}

	// Severity is read back as the word it prints, which is what a caller
	// outside Go gets.
	var got struct {
		Source   string
		Path     string
		Errors   int
		Warnings int
		Summary  string
		Findings []struct {
			Kind     string
			Severity string
			Token    string
			Operator string
			Line     int
			Pattern  string
			Wording  string
			Source   string
			Message  string
		}
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decoding %q: %v", out, err)
	}
	if got.Path != lint.DefaultPath || got.Source == "" || got.Summary == "" {
		t.Errorf("report = %+v, want the source, the path and the summary", got)
	}
	if got.Errors != 1 || got.Warnings != 1 {
		t.Errorf("errors = %d, warnings = %d, want one of each", got.Errors, got.Warnings)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("findings = %+v, want both of them", got.Findings)
	}
	severities := make(map[string]bool)
	for _, f := range got.Findings {
		severities[f.Severity] = true
		if f.Token != "Claude-SearchBot" || f.Line != 2 || f.Pattern != "/" {
			t.Errorf("finding = %+v, want the token and the line the rule was read from", f)
		}
		if f.Kind == "" || f.Operator == "" || f.Wording == "" || f.Source == "" || f.Message == "" {
			t.Errorf("finding = %+v, want the vendor wording and the document it was read from", f)
		}
	}
	if !severities["error"] || !severities["warning"] {
		t.Errorf("severities = %v, want both spelled out", severities)
	}
}

func TestLintReadsTheRulesForThePathGiven(t *testing.T) {
	path := fixture(t, "User-agent: OAI-SearchBot\nDisallow: /articles/\n")

	code, out, err := exec(t, command{}, "lint", path)
	if err != nil || code != exitOK || out != "no findings\n" {
		t.Fatalf("run = (%d, %q, %v), want nothing reported for %q", code, out, err, lint.DefaultPath)
	}

	code, out, err = exec(t, command{}, "lint", "-path", "/articles/one", path)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != exitOK {
		t.Errorf("exit code = %d, want %d: a contradiction to weigh is not a failure", code, exitOK)
	}
	if !strings.Contains(out, "warning search-disallowed-training-allowed OAI-SearchBot") {
		t.Errorf("output = %q, want the rule read for the path given", out)
	}
}

func TestLintAURLFollowsFiveRedirectsAndNoMore(t *testing.T) {
	cases := []struct {
		name string
		hops int
		want int
	}{
		{"five hops are followed", 5, exitOK},
		{"the sixth is refused", 6, exitFailure},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := hopServer(t, c.hops)
			code, out, err := exec(t, command{policy: allowAll}, "lint", srv.URL+"/0")
			if code != c.want {
				t.Errorf("exit code = %d, want %d (%v)", code, c.want, err)
			}
			if c.want == exitOK {
				if err != nil {
					t.Fatalf("run: %v", err)
				}
				if out != "no findings\n" {
					t.Errorf("output = %q, want the file the chain ended at", out)
				}
				return
			}
			if !errors.Is(err, errRedirects) {
				t.Fatalf("error = %v, want it to be %v", err, errRedirects)
			}
		})
	}
}

func TestLintChecksTheAddressOfEveryHop(t *testing.T) {
	var (
		mu      sync.Mutex
		checked []netip.Addr
	)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "second.example") {
			fmt.Fprint(w, cleanRobots)
			return
		}
		_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "http://second.example:"+port+"/robots.txt", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("reading the listener address: %v", err)
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	c := command{
		resolver: resolver{
			"first.example":  {loopback},
			"second.example": {loopback},
		},
		policy: func(addr netip.Addr) error {
			mu.Lock()
			defer mu.Unlock()
			checked = append(checked, addr)
			return nil
		},
	}

	code, out, err := exec(t, c, "lint", "http://first.example:"+port+"/robots.txt")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != exitOK || out != "no findings\n" {
		t.Errorf("run = (%d, %q), want the file the redirect led to", code, out)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(checked) != 2 {
		t.Errorf("addresses checked = %v, want the policy consulted for each hop", checked)
	}
}

func TestLintRefusesAURLInsideTheNetworkDoingTheFetch(t *testing.T) {
	srv := hopServer(t, 0)
	code, _, err := exec(t, command{}, "lint", srv.URL+"/0")
	if !errors.Is(err, webbotauth.ErrAddressNotAllowed) {
		t.Fatalf("error = %v, want it to be %v", err, webbotauth.ErrAddressNotAllowed)
	}
	if code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
}

func TestLintRefusesASchemeItDoesNotFetch(t *testing.T) {
	code, _, err := exec(t, command{}, "lint", "ftp://example.com/robots.txt")
	if !errors.Is(err, errScheme) {
		t.Fatalf("error = %v, want it to be %v", err, errScheme)
	}
	if code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
}

func TestLintRefusesAHopToAnotherScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://example.com/robots.txt", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	code, _, err := exec(t, command{policy: allowAll}, "lint", srv.URL+"/robots.txt")
	if !errors.Is(err, errScheme) {
		t.Fatalf("error = %v, want it to be %v: every hop is checked again", err, errScheme)
	}
	if code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
}

func TestLintReadsAStatusAsPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	code, _, err := exec(t, command{policy: allowAll}, "lint", srv.URL+"/robots.txt")
	if err == nil {
		t.Fatal("no error, want the status read as policy: there is no file to lint")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error = %v, want it to name the status", err)
	}
	if code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"check"}, {"lint"}, {"lint", "a", "b"}, {"lint", "-unknown"}} {
		code, _, err := exec(t, command{}, args...)
		if err == nil {
			t.Errorf("run(%v) = no error, want usage", args)
		}
		if code != exitFailure {
			t.Errorf("run(%v) exit code = %d, want %d", args, code, exitFailure)
		}
	}
	for _, args := range [][]string{{"help"}, {"lint", "-h"}} {
		code, out, err := exec(t, command{}, args...)
		if err != nil || code != exitOK || !strings.HasPrefix(out, "usage:") {
			t.Errorf("run(%v) = (%d, %q, %v), want the usage text", args, code, out, err)
		}
	}
}
