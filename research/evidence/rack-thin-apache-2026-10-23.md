# Rack/Thin → Apache pooled-response evidence

Status: evidence preserved for coordinated disclosure research. This is not yet a CVE claim.

## Reproducible real-application result

- Repository: `Johnny-Kao/apache-httpd-candidate-b-research-public`
- Tested commit: [`9b9d222`](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/commit/9b9d222a7bc1772ec47ab3b3a1027b92c726f814)
- Workflow: [run 39944244892](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39944244892)
- CI environment: GitHub-hosted Ubuntu runner
- Components: Apache HTTP Server 2.4.69, Rack 3.2.5, Thin, the checked-in Rack/Thin fixture

The attacker-side request is an ordinary URL request to the Rack application:

```text
GET /missing/<percent-encoded UTF-8 path data> HTTP/1.1
Host: tenant-a.example
Connection: keep-alive
```

Rack::Files reflects the path in a 404 body and declares a character count as
`Content-Length`. Thin then sends the remaining bytes later through its
streaming body. The direct backend check recorded:

```text
declared=125
actual=285
mismatch=True
```

With Apache backend connection reuse enabled, the subsequent unrelated
`tenant-b.example` response contained bytes from A's delayed tail:

```text
cross_tenant_hits=76/100
apache_errors=0/100
boundary=observed
```

With `disablereuse=On`:

```text
cross_tenant_hits=0/20
apache_errors=0/20
boundary=not_observed
```

The observed B body was an A-controlled UTF-8 tail, for example:

```text
98 83 e2 98 83 e2 98 83 e2 98
```

This establishes a real server-side cross-tenant response-body contamination
chain:

```text
ordinary A URL input
  -> Rack/Thin malformed length + delayed bytes
  -> Apache pooled backend connection
  -> unrelated B response body contains A bytes
```

## Impact boundary currently established

The result is a response-integrity/isolation failure. It does not yet prove
that an attacker can read B's secret data, modify B response headers, or run
JavaScript in a B-origin browser.

The same workflow's HTML-marker variant showed that Thin can directly emit a
delayed `<script>` tail (`declared=265`, `actual=671`), but Apache produced
`0/20` cross-tenant marker hits and `20/20` response errors for that variant.
Therefore the HTML/XSS path is still unproven and must not be claimed.

## Reproduction and reporting notes

The raw CI log is retained by GitHub at the workflow link above. The exact
test implementation is `research/test_rack_thin_apache.py`; the backend
fixture is `research/rack_thin_fixture/config.ru`. The reuse-disabled result
is the required control. The earlier synthetic impact probe is separate and
must not be presented as proof of a real application trigger.

## Remaining High-severity question

The next test must preserve the proven body-contamination timing while placing
an HTML marker after a harmless non-status prefix, then validate the victim
body and browser separately. A positive result would establish an attacker-
controlled script under the victim origin; a negative result leaves the issue
as server-side response contamination without a demonstrated High impact.
