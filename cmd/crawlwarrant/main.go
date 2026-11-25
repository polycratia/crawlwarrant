// Command crawlwarrant reads a robots.txt file against what crawler operators
// publish about the tokens it names and reports where the file contradicts
// itself.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"

	"github.com/polycratia/crawlwarrant/lint"
	"github.com/polycratia/crawlwarrant/robots"
	"github.com/polycratia/crawlwarrant/webbotauth"
)

// Exit codes. A warning is not a failure: a site may well mean it.
const (
	exitOK      = 0
	exitErrors  = 1
	exitFailure = 2
)

// DefaultTimeout bounds one fetch when -timeout gives none.
const DefaultTimeout = 10 * time.Second

const usage = `usage: crawlwarrant lint [flags] <path or URL>

lint reads a robots.txt file against what crawler operators publish about the
tokens it names. A path is read from disk; an http or https URL is fetched
through the address policy a key directory fetch dials under, following up to
the five redirects RFC 9309 asks for, with every hop checked again.

flags:
  -citation        the site wants to be cited in AI answers, which makes a
                   disallowed search-index crawler an error, not a warning
  -json            print the findings as JSON
  -path string     path the rules are read for (default "/")
  -timeout value   bound on one fetch (default 10s)

exit codes: 0 nothing worse than a warning, 1 at least one error, 2 the file
could not be read.
`

var (
	errScheme    = errors.New("a robots.txt is fetched over http or https only")
	errRedirects = fmt.Errorf("a robots.txt fetch follows the %d redirects RFC 9309 asks for and no more", robots.MaxRedirects)
)

func main() {
	c := command{out: os.Stdout}
	code, err := c.run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "crawlwarrant: %v\n", err)
	}
	os.Exit(code)
}

// command is one run of the tool: where output goes and, for a URL, the
// address policy and the resolver a fetch dials under. The tests set their own
// of each, so none of them reaches a network a published policy would refuse.
type command struct {
	out      io.Writer
	policy   func(netip.Addr) error
	resolver webbotauth.Resolver
}

// report is what -json prints.
type report struct {
	Source   string         `json:"source"`
	Path     string         `json:"path"`
	Errors   int            `json:"errors"`
	Warnings int            `json:"warnings"`
	Summary  string         `json:"summary"`
	Findings []lint.Finding `json:"findings"`
}

func (c command) run(args []string) (int, error) {
	if len(args) == 0 {
		return exitFailure, fmt.Errorf("a command is needed\n\n%s", usage)
	}
	switch args[0] {
	case "lint":
		return c.lint(args[1:])
	case "help", "-h", "-help", "--help":
		fmt.Fprint(c.out, usage)
		return exitOK, nil
	}
	return exitFailure, fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
}

func (c command) lint(args []string) (int, error) {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	var (
		asJSON   = fs.Bool("json", false, "print the findings as JSON")
		path     = fs.String("path", lint.DefaultPath, "path the rules are read for")
		citation = fs.Bool("citation", false, "the site wants to be cited in AI answers")
		timeout  = fs.Duration("timeout", DefaultTimeout, "bound on one fetch")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(c.out, usage)
			return exitOK, nil
		}
		return exitFailure, fmt.Errorf("%v\n\n%s", err, usage)
	}
	if fs.NArg() != 1 {
		return exitFailure, fmt.Errorf("lint reads one robots.txt file or URL\n\n%s", usage)
	}

	source := fs.Arg(0)
	opts := lint.Options{Path: *path, WantCitation: *citation}
	if opts.Path == "" {
		opts.Path = lint.DefaultPath
	}
	file, err := c.read(context.Background(), source, *timeout)
	if err != nil {
		return exitFailure, err
	}
	findings := lint.Check(file, opts)
	if err := c.print(source, opts, findings, *asJSON); err != nil {
		return exitFailure, err
	}
	if errs, _ := lint.Count(findings); errs > 0 {
		return exitErrors, nil
	}
	return exitOK, nil
}

func (c command) print(source string, opts lint.Options, findings []lint.Finding, asJSON bool) error {
	if !asJSON {
		_, err := io.WriteString(c.out, lint.Text(findings))
		return err
	}
	errs, warnings := lint.Count(findings)
	summary := lint.Summary(findings)
	if findings == nil {
		findings = []lint.Finding{}
	}
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	return enc.Encode(report{
		Source:   source,
		Path:     opts.Path,
		Errors:   errs,
		Warnings: warnings,
		Summary:  summary,
		Findings: findings,
	})
}

// read returns the parsed file the argument names: a path on disk, or an http
// or https URL fetched under the address policy.
func (c command) read(ctx context.Context, source string, timeout time.Duration) (robots.File, error) {
	if u, err := url.Parse(source); err == nil && u.Scheme != "" {
		return c.fetch(ctx, source, timeout)
	}
	f, err := os.Open(source)
	if err != nil {
		return robots.File{}, err
	}
	defer f.Close()
	file, err := robots.Parse(f)
	if err != nil {
		return robots.File{}, fmt.Errorf("reading %s: %w", source, err)
	}
	return file, nil
}

func (c command) fetch(ctx context.Context, target string, timeout time.Duration) (robots.File, error) {
	if err := allowedScheme(target); err != nil {
		return robots.File{}, err
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	dialer := &webbotauth.Dialer{Resolver: c.resolver, Policy: c.policy}
	redirects := 0
	client := &http.Client{
		Transport: &http.Transport{DialContext: dialer.DialContext},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects = len(via)
			if redirects > robots.MaxRedirects {
				return fmt.Errorf("%s is redirect %d: %w", req.URL, redirects, errRedirects)
			}
			return allowedScheme(req.URL.String())
		},
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return robots.File{}, fmt.Errorf("%s: %w", target, err)
	}
	req.Header.Set("Accept", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		return robots.File{}, fmt.Errorf("fetching %s: %w", target, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, robots.MaxBytes+1))
	if err != nil {
		return robots.File{}, fmt.Errorf("reading %s: %w", target, err)
	}
	p := robots.FromFetch(robots.Outcome{Status: resp.StatusCode, Redirects: redirects, Body: body})
	if p.Effect != robots.EffectRules {
		return robots.File{}, fmt.Errorf("%s: %s", target, p.Reason)
	}
	return p.File, nil
}

// allowedScheme refuses a URL this command does not fetch. Every redirect hop
// goes through it again, because a hop is where a fetch is aimed somewhere
// else.
func allowedScheme(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q: %v: %w", raw, err, errScheme)
	}
	switch u.Scheme {
	case "http", "https":
		return nil
	}
	return fmt.Errorf("%q names the scheme %q: %w", raw, u.Scheme, errScheme)
}
