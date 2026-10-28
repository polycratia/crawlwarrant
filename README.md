# crawlwarrant

crawlwarrant verifies which AI crawler is actually at the door and what the site allowed it: identity checks against published IP ranges and signatures, a machine-readable access policy, and a three-bucket audit of access logs (verified and compliant, verified and violating, impostors claiming a crawler's name). This module holds the `robots` package, which parses robots.txt, picks the group that governs a crawler, applies RFC 9309 matching, reads the `Content-Signal` lines of that group, and reads a fetch status as policy of its own, returning the rule or the status that decided a path so an audit can say why.

## robots

```go
file, err := robots.Parse(r)
if err != nil {
	return err
}
group, ok := file.Select("ExampleBot")
if !ok {
	fmt.Println("no group names ExampleBot and the file has no * group: everything is allowed")
}
if rule, ok := group.Match("/admin/page"); ok {
	fmt.Printf("%s %q (line %d)\n", rule.Kind, rule.Pattern, rule.Line)
} else {
	fmt.Println("allowed: no rule applies")
}
```

### Groups

A group is the consecutive `User-agent` lines of a record together with the rules that follow them. Every group that names the same product token is merged into one, in file order, as RFC 9309, Section 2.2.1, requires, so a crawler whose rules are split across the file still gets all of them. `Select` compares product tokens case-insensitively and as a whole, never as a substring of a `User-agent` header; when no group names the token the `*` group governs, and when the file has neither the group returned has no rules, which allows every path.

A value that begins with a product token and continues with something else, such as `Googlebot/1.2`, names the group `googlebot` and is reported. A value with no product token prefix, such as `*bot*`, names nothing: it is reported as `non-portable-token`, because it is not an RFC 9309 product token, Google's parser matches nothing, and other crawlers may match substrings.

`Parse` reports what it noticed as findings rather than errors: non-portable values, an `Allow`, `Disallow` or `Content-Signal` line that precedes every `User-agent` line (reported and dropped, never attached to the group that follows), and input past 500 KiB, which is ignored and reported as `truncated` with the byte offset where parsing stopped.

### Matching

Matching follows RFC 9309, Section 2.2.2: the matching rule with the most octets wins, an allow rule wins a tie against a disallow rule of the same length, `*` matches any sequence of octets, a trailing `$` anchors the end, an empty `Disallow` value matches nothing, and `/robots.txt` is always allowed. Pattern and path are compared after percent-encoding normalization, with escapes of unreserved characters decoded and every other escape uppercased.

### Content signals

A `Content-Signal` line says what a site allows beyond the crawl itself. `Parse` reads it into the group it appears in, beside the allow and disallow lines, and `Group.Signals` carries the result:

```go
group, _ := file.Select("ExampleBot")
fmt.Println(group.Signals.Search, group.Signals.AIInput, group.Signals.AITrain) // yes unset no
```

The Content Signals Policy defines `search`, `ai-input` and `ai-train`, each taking `yes` or `no`. A key the group never gave stays `SignalUnset`: it grants nothing, refuses nothing, and is never reported as a `no`. So the managed form `search=yes, ai-train=no` has said nothing at all about `ai-input` — and a blank line, or no line, leaves all three open. AI summaries and retrieval-augmented generation fall under `ai-input` rather than `search`, because the policy defines search as indexing and returning links and short excerpts, and excludes AI-generated summaries from it.

A key the policy does not define is ignored and reported as `unknown-signal-key`, a value that is neither `yes` nor `no` as `malformed-signal`; the rest of the line still counts. A key the same group gives twice with different values resolves to `no`, the value that restricts, and is reported as `signal-conflict` naming both lines.

The policy publishes its example under `User-Agent: *` only and says nothing about a line in another group, so scoping each line to the group it appears in is this parser's choice, noted where `Parse` handles the field.

### Fetch status

A fetch status is policy in itself. `FromFetch` turns a recorded fetch into a `Policy`, from values the caller already has, so nothing here touches the network:

```go
p := robots.FromFetch(robots.Outcome{Status: 503})
fmt.Println(p.Effect, "-", p.Reason) // disallow all - status 503: currently disallowing everything
```

A 2xx parses the body and the rules in `p.File` decide (Section 2.3.1.1). Up to five consecutive redirects are followed; a sixth, or a chain that ends on a redirect, leaves the file unavailable (Section 2.3.1.2). Any other 4xx is unavailable too, so everything is allowed (Section 2.3.1.3). A 5xx, a transport error, or no response at all is a complete disallow while it lasts (Section 2.3.1.4). Every `Policy` carries the `Reason` and the `Source` it came from, URL included.

Status 429 is the one status published sources read differently, so it is a row of the `Divergences` table rather than a decision: RFC 9309 reads it as a 4xx and allows everything, while Google documents it with the server errors and disallows everything. The `Policy` carries both readings and no `Effect` of its own, and the caller picks one:

```go
p, err := robots.FromFetch(robots.Outcome{Status: 429}).Under(robots.ReadingGoogle)
```

`Under` returns `ErrReadingRequired` for the zero `Reading`: there is no default.

Freshness and long unreachability are rows of data, not a timer. `FreshFor` holds the 24-hour caching limits, and `WhileUnreachable` holds the RFC's 30-day example alongside Google's 12-hour then 30-day sequence, each row with the source it came from. A caller that tracks how long a site has been failing decides which row it is on.

Run the tests with `go test ./...`.

---

By polycratia — <https://polycratia.com>
