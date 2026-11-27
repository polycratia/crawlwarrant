# crawlwarrant

crawlwarrant verifies which AI crawler is actually at the door and what the site allowed it: identity checks against published IP ranges and signatures, a machine-readable access policy, and a three-bucket audit of access logs (verified and compliant, verified and violating, impostors claiming a crawler's name). This module holds the `robots` package, which parses robots.txt, picks the group that governs a crawler, applies RFC 9309 matching, reads the `Content-Signal` lines of that group, and reads a fetch status as policy of its own, returning the rule or the status that decided a path so an audit can say why; the `purpose` package, which holds what each published crawler token is for as cited rows of data; the `identity` package, which settles who a request is before it applies what the site allowed, and never puts a vendor's group in force without evidence; the `webbotauth` package, which reads the header fields a Web Bot Auth request carries as the structured fields they are, fetches the keys a crawler publishes, and verifies the signature they describe against them; and the `lint` package, behind the `crawlwarrant` command, which reads a robots.txt file against what the operators publish about the tokens it names and reports where the file contradicts itself.

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

## purpose

`purpose` holds what each published crawler token is for: the operator, the purpose (`training`, `search-index`, `user-initiated`, `control-token`, `ads`), whether the token fetches at all, whether robots.txt applies to it (`yes`, `may-not`, `unknown`), the operator's IP range file, the reverse-DNS suffixes a lookup must end in, and the `Signature-Agent` URL whose key directory signs its requests. Every row also carries the operator's own wording for what refusing the token does, names the document it was read from and the day it was read, and nothing in the table is fetched at runtime.

```go
res, ok := purpose.Lookup("Google-Extended", time.Now())
if !ok {
	fmt.Println("no row names that token")
	return
}
fmt.Println(res.Row.Operator, res.Row.Purpose, res.Row.Fetches) // Google control-token false
for _, r := range res.Reasons {
	fmt.Println(r.Kind, "-", r.Message)
}
```

`Lookup` compares product tokens case-insensitively and as a whole, like `robots.Select`. A token the table does not name is unlisted, not an impostor: `ok` is false and the caller decides what that means.

`Google-Extended` is in the table with `Fetches` false and no range file, because it is a robots.txt control token rather than a crawler: it names a use a site can refuse, and no request is ever sent under it. A request whose `User-Agent` claims it matches no published range by construction, so `Lookup` returns the `token never fetches` reason instead of leaving a caller to attempt a verification that cannot succeed. The same way, a fetch a person asked for carries `may-not` (`ChatGPT-User`) or `unknown` (`Perplexity-User`) with a reason, so an audit does not record a passed rule as a violation the operator never agreed to.

Rows age in the open. All of them were read on 2026-10-19, and once a row is more than 180 days older than the time passed to `Lookup`, the `purpose row stale` reason is added, naming the source to read again. The row is still returned — it is what was published — but its age travels with it.

## identity

`identity` settles who a request is before it applies what the site allowed. Evidence is `signed`, `range`, `fcrdns`, `claimant` or `anonymous`, and only the first three tie a request to an operator, so only they put that operator's group in force:

```go
v := identity.Decide(req, policy, identity.Signed("GPTBot", "https://chatgpt.com/.well-known/http-message-signatures-directory"))
fmt.Println(v.Verified, v.Group.Token, v.Allowed) // true gptbot true
for _, r := range v.Reasons {
	fmt.Println(r.Kind, "-", r.Message)
}
```

A request whose `User-Agent` names a published token and proves nothing further is a claimant: it gets the `*` group, and the chain records `claimed GPTBot, unverified`. It is not called an impostor, because nothing about it was disproved — it was only never verified. A request that names no published token is anonymous and gets the `*` group as well. When evidence verifies one token while the header claims another, the verified token decides and the chain says so.

The `Verdict` is the ordered chain of reasons that produced it: how identity was settled, which group that put in force, then what decided the path, with `Deciding` returning the last of them.

### Range snapshots

A `Snapshot` is one recorded fetch of the IP range file an operator publishes for its crawlers, with the dates a match has to be read against: the `creationTime` the operator put in the file, when we fetched it, and the URL that answered.

```go
snap, err := identity.Load(identity.Snapshot{
	Operator:     "OpenAI",
	Tokens:       []string{"GPTBot"},
	URL:          "https://openai.com/gptbot.json",
	CreationTime: creationTime,
	FetchedAt:    time.Now(),
	Prefixes:     prefixes,
})
if err != nil {
	return err
}
ev := snap.Verify(ip, "GPTBot", time.Now())
```

`Load` refuses a general cloud provider list — AWS `ip-ranges.json`, Google Cloud `cloud.json`, Google's `goog.json`, Azure service tags — with `ErrCloudRangeList`, and refuses one a redirect led to the same way. Those files cover every address a customer of that provider can rent, so a match proves hosting, not a crawler, and the refusal belongs at load rather than at a request the file cannot speak for.

Past the snapshot's `MaxAge`, 24 hours unless it sets its own, nothing is verified against it until it is fetched again. A file another URL answered for still verifies, with `range source redirected` in the chain: it is re-verified at its published URL before it is trusted again. A file that carried no `creationTime` is flagged too, because how old the operator's own data is cannot be read from it. And a file several tokens share verifies the operator, not which of its products sent the request, which the chain says in as many words.

### Forward-confirmed reverse DNS

`FCrDNS` goes through an injected `Resolver`, which `*net.Resolver` satisfies and a test supplies its own of, so no test here touches live DNS. The address must reverse to a name inside one of the suffixes the operator publishes, and that name must resolve back to the address. A resolver that fails verifies nothing and is held against nobody: the failure travels as a reason.

### Middleware

`Middleware` decides every request, stores the `Verdict` in its context for `FromContext`, and blocks with 403 only when `opts.Enforce` is set. Left unset, every request is served and the verdict is only the record of what the policy said.

## webbotauth

`webbotauth` reads the header fields a Web Bot Auth request carries: `Signature-Agent`, which names where the keys that signed the request are published, and `Signature-Input`, which says what each signature covers.

```go
sa, err := webbotauth.ParseSignatureAgent(r.Header.Get("Signature-Agent"))
if err != nil {
	return err
}
for _, a := range sa.Agents {
	fmt.Println(a.Label, a.URL, a.Type) // sig1 https://chatgpt.com/.well-known/http-message-signatures-directory directory
}

sigs, err := webbotauth.ParseSignatureInput(r.Header.Get("Signature-Input"))
if err != nil {
	return err
}
fmt.Println(sigs[0].KeyID, sigs[0].Tag, sigs[0].Created, sigs[0].Components[0].Name)
```

A `Signature-Agent` member is a string holding an https URL with an optional `type` parameter. A member that gives no type is a `directory`, `jwks_uri` and `cimd` are recognised, and any other type is kept with the member as `TypeOther` with the spelling the field used: a document this package cannot read is not a malformed field. A plain `http` URL is refused with `ErrNotHTTPS`, because keys fetched over a connection nobody authenticated prove nothing, and a member that is not a string — a token, an integer, an inner list — with `ErrNotAString`.

The bare string form, which ChatGPT agent sends as `Signature-Agent: "https://chatgpt.com"`, is accepted and reported as `Legacy`. It is read on input only and never produced, so a caller can serve the senders that still send it without putting the superseded form back on the wire.

`ParseSignatureInput` returns, per label, the covered components with the parameters each one carried, such as `req` or `sf`, and the `created`, `expires`, `keyid`, `tag` and `nonce` parameters of the signature. A label the field gave no `created` for keeps the zero time rather than a guess at one.

### Verifying a signature

`Verify` checks the signature a request carries against the keys a directory published, as of the time passed to it, and returns the `Verdict` of the signature it verified or the refusal that stopped it. The revision it follows is pinned in `Draft`, so a verdict says which document it was reached under.

```go
keys := webbotauth.NewKeyring()
thumbprint, err := keys.Add("https://crawler.example/.well-known/http-message-signatures-directory", jwk)
if err != nil {
	return err
}

v, err := webbotauth.Verify(r, keys, time.Now())
if err != nil {
	return err
}
fmt.Println(v.Directory, v.Thumbprint == thumbprint, v.Components)
for _, reason := range v.Reasons {
	fmt.Println(reason.Kind, "-", reason.Message)
}
```

The signature that gets verified is the one tagged `web-bot-auth`. A request may carry others, and a `Signature-Input` naming none is refused with `ErrTag` rather than read under a tag meant for another protocol. `created` and `expires` are both required (`ErrMissingParameter`) and checked against `now` with `Keyring.Skew`, `DefaultSkew` of five seconds when the keyring sets none; a window that has closed, one that has not opened, and an `expires` before its `created` are all `ErrOutsideWindow`.

The covered components must include `@authority` or `@target-uri`, which binds the signature to the host it was sent to, and `signature-agent`, the field naming the key directory of the label; anything less is `ErrCoveredComponents`, as is a covered field the request does not carry. The signature base is rebuilt from the request per RFC 9421, Section 2.5, with the signature parameters as the field spelled them, and the bytes that verified travel in `Verdict.Base` so an audit can read them. A covered component this package does not rebuild — `@status` on a request, or a component carrying a parameter such as `sf` — is `ErrUnsupportedComponent`: a base nobody can rebuild is unverifiable, which is not the same as a signature that is wrong.

`keyid` is not a name the sender is taken at its word on. It must equal the RFC 7638 thumbprint computed here from the Ed25519 JWK (RFC 8037), and the key is then looked up by the directory URL and that thumbprint together, because a key proves nothing about a directory that did not publish it. `Keyring.Add` records a key under the thumbprint it computes and refuses a published `kid` that is not it, with `ErrThumbprintMismatch`. Only Ed25519 verifies: an `alg` naming HMAC or anything else is `ErrAlgorithm`, and so is key material that is not 32 bytes of canonically encoded unpadded base64url (`ErrKeyMaterial`), an encoding that would otherwise thumbprint to a second name for one key.

What a verified signature leaves open travels in the verdict as reasons rather than refusals. With no `ReplayCache` configured nothing checks a nonce, so the verdict carries `replayable within window`: the signature can be sent again until it expires. A cache is opt-in, keyed by the nonce when the signature gives one and by the signature bytes when it does not, and one it has already seen is `ErrReplay`. A lifetime above `MaxLifetime`, the 24 hours the draft asks for, is reported as `lifetime above 24 hours` and still verified, and a directory named by the legacy bare string form of `Signature-Agent` as `legacy signature-agent`.

### Fetching a key directory

`Directory` fetches the keys a crawler publishes at `DirectoryPath`, `/.well-known/http-message-signatures-directory`, and caches them by directory URL and thumbprint together. A URL naming a host alone — which the legacy bare string form of `Signature-Agent` does — is read as that path under it, and a URL that is not https is refused with `ErrNotHTTPS` before any request is made.

```go
dir := webbotauth.NewDirectory(&http.Transport{
	DialContext: (&webbotauth.Dialer{}).DialContext,
})
keys, err := dir.Keys(ctx, "https://crawler.example", time.Now())
if err != nil {
	return err
}
fmt.Println(keys.URL, keys.Thumbprints, keys.FetchedAt)

v, err := webbotauth.Verify(r, dir.Keyring("https://crawler.example"), time.Now())
```

Only a 200 is a document to read. Every other status is a discovery failure, `ErrDirectoryStatus`, and a redirect is refused with `ErrDirectoryRedirect` instead of followed — the deliberate inverse of the five hops a robots.txt fetch follows, pinned by a test, because the file being fetched here is the one that decides which key counts. `Directory` holds a `RoundTripper` rather than a `Client` for that reason: there is no redirect policy to configure, and a `Directory` with none set refuses with `ErrNoTransport`.

Fetched keys are used for `TTL`, `DefaultDirectoryTTL` of an hour when unset, and then the directory is asked again. A refresh that fails evicts nothing: the keys already cached are returned with the `key refresh failed` reason naming the failure, the fetch they came from, and when the next one will be attempted. A refresh that succeeds replaces them, so a key the new document omits is revoked by its absence. A failure with no keys behind it is remembered for `NegativeTTL`, `DefaultNegativeTTL` of five minutes when unset, and a `Retry-After` the response gave is honoured instead, as seconds or as an HTTP date.

A body above `MaxBytes` is `ErrDirectoryTooLarge` and more than `MaxKeys` keys is `ErrTooManyKeys`, at 64 KiB and 32 keys unless the `Directory` sets its own; a refused document caches nothing. A published key this package cannot verify with — a key type other than `OKP` on Ed25519, key material that is not canonical, or a `kid` that is not the thumbprint of the key beside it — is skipped with the `unusable published key` reason and the rest of the document is kept. A document with no usable key at all is `ErrDirectoryBody`.

Every fetch is bounded by `Timeout`, `DefaultDirectoryTimeout` of ten seconds when unset, and concurrent calls for one directory are coalesced into a single fetch that all of them read.

`Dialer` resolves the name itself and checks each address against its `Policy` before dialing it, so neither a DNS record nor a URL can aim a fetch at the network the fetch is made from. `AllowedAddress` is that policy by default: it refuses loopback, unspecified, link-local, multicast, private and carrier-grade NAT addresses with `ErrAddressNotAllowed`, IPv4-mapped forms included. Both the `Resolver` and the dial are injected, so the tests here run against a `RoundTripper` and an address policy of their own and never reach the network.

### Structured fields

Both fields are RFC 9651 structured fields, parsed by `internal/sfv`, which reads the subset Web Bot Auth needs: dictionaries, inner lists, strings, tokens, integers, byte sequences, booleans and the parameters of each. A form the subset leaves out, a decimal or a date among them, is refused like any other malformed input: with the byte offset it was refused at, so a caller can quote the field around it. The offset never points past the end of the input, which `FuzzDictionary` asserts for any input at all, along with the parser never panicking:

```
go test -run FuzzDictionary -fuzz FuzzDictionary ./internal/sfv
```

## lint

`lint` reads a parsed robots.txt file against the `purpose` table and reports where the file contradicts itself. A finding names the token, the line the rule was read from, and the operator's own account of what refusing that token does, so a report quotes the vendor rather than guessing at the consequence:

```go
findings := lint.Check(file, lint.Options{Path: "/articles/one", WantCitation: true})
fmt.Print(lint.Text(findings))
errs, warnings := lint.Count(findings)
```

The rules are read for one path, `DefaultPath` of `/` when `Options.Path` names none, because a file that refuses a crawler under `/articles/` has said nothing about the rest of the site. Five kinds are reported:

- `ai-input-granted-search-disallowed`: the group grants `ai-input=yes` while disallowing a search-index crawler, so the page may be answered from while the crawler that builds the index those answers link back to is refused.
- `search-disallowed-training-allowed`: an operator's training crawler is allowed while its search crawler is disallowed — `GPTBot` collects pages while `OAI-SearchBot` is kept out of ChatGPT search answers, where the site could still have appeared as a navigational link.
- `control-token-disallowed`: a disallowed token no request is ever sent under, `Google-Extended` among them, which crawls nothing and does not affect inclusion or ranking in Google Search.
- `robots-may-not-apply-disallowed`: a disallowed token whose operator publishes that robots.txt may not apply to it, as OpenAI does of `ChatGPT-User`, because the fetch is one a person asked for.
- `citation-wanted-search-disallowed`: a disallowed search-index crawler for a site that asked to be cited.

Everything but the last is a `warning`: a contradiction to weigh, because a site may well mean it. `Options.WantCitation` says the site wants to be cited in AI answers, and a disallowed search-index crawler then contradicts what the caller asked for rather than only what the file says, so each one is an `error` naming the token. Golden files under `lint/testdata` pin the text of every finding.

### The command

```
go run ./cmd/crawlwarrant lint [-citation] [-json] [-path /] [-timeout 10s] <path or URL>
```

A path is read from disk. An `http` or `https` URL is fetched through the address policy a key directory fetch dials under, so neither a DNS record nor a redirect can aim the fetch at the network it is made from, and up to the five redirects RFC 9309 asks for are followed with every hop checked again. The status is read as policy by `robots.FromFetch`: an outcome that reaches no file is reported rather than linted. `-json` prints the findings with the source, the path and the counts, severities spelled out as the words they print. The exit code is 0 when nothing worse than a warning was found, 1 when at least one finding is an error, and 2 when the file could not be read.

Run the tests with `go test ./...`.

---

By polycratia — <https://polycratia.com>
