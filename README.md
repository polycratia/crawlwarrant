# crawlwarrant

crawlwarrant verifies which AI crawler is actually at the door and what the site allowed it: identity checks against published IP ranges and signatures, a machine-readable access policy, and a three-bucket audit of access logs (verified and compliant, verified and violating, impostors claiming a crawler's name). This module holds the `robots` package, which parses robots.txt and applies RFC 9309 matching, returning the rule that decided a path so an audit can say why.

## robots

```go
groups, err := robots.Parse(file)
if err != nil {
	return err
}
if rule, ok := groups[0].Match("/admin/page"); ok {
	fmt.Printf("%s %q (line %d)\n", rule.Kind, rule.Pattern, rule.Line)
} else {
	fmt.Println("allowed: no rule applies")
}
```

Matching follows RFC 9309, Section 2.2.2: the matching rule with the most octets wins, an allow rule wins a tie against a disallow rule of the same length, `*` matches any sequence of octets, a trailing `$` anchors the end, an empty `Disallow` value matches nothing, and `/robots.txt` is always allowed. Pattern and path are compared after percent-encoding normalization, with escapes of unreserved characters decoded and every other escape uppercased.

Run the tests with `go test ./...`.

---

By polycratia — <https://polycratia.com>
