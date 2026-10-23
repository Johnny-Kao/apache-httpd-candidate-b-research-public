# Source-level root-cause verification

## Decision scope

This report reviews Apache HTTP Server 2.4.69 at source commit
[`1e06e9860794ce39605b79a0a787abfe084e5677`](https://github.com/apache/httpd/tree/1e06e9860794ce39605b79a0a787abfe084e5677)
against public CI observations. Runtime evidence comes from
[39950101256](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39950101256)
and
[39950603922](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39950603922).

## Hypothesis

If a backend sends a syntactically valid but too-small `Content-Length`, and
the remaining bytes arrive after Apache has checked an idle pooled connection,
`mod_proxy_http` may release the connection as reusable and later consume the
remaining bytes as part of an unrelated victim response.

Expected invariant: bytes belonging to request A must never be delivered as
the response body or headers for request B. The RFC and source analysis below
separate the backend framing violation from Apache's isolation behavior.

## Exact source points

The relevant Apache 2.4.69 implementation points are:

1. [`http_filters.c#L575-L657`](https://github.com/apache/httpd/blob/1e06e9860794ce39605b79a0a787abfe084e5677/modules/http/http_filters.c#L575-L657)
   limits reads to `ctx->remaining`, decrements it, and inserts EOS when a
   `Content-Length` body reaches zero. This is where Apache treats the
   declared response body as complete.
2. [`mod_proxy_http.c#L1644-L1809`](https://github.com/apache/httpd/blob/1e06e9860794ce39605b79a0a787abfe084e5677/modules/proxy/mod_proxy_http.c#L1644-L1809)
   copies response headers, reads the backend body through the HTTP input
   filter, passes it to the client, and releases the backend connection after
   the body loop reaches EOS.
3. [`proxy_util.c#L1616-L1695`](https://github.com/apache/httpd/blob/1e06e9860794ce39605b79a0a787abfe084e5677/modules/proxy/proxy_util.c#L1616-L1695)
   defines a connection as potentially reusable unless it is marked closed or
   `disablereuse` is enabled. `connection_cleanup()` does not call the
   pending-data check before pooling the connection.
4. [`mod_proxy_http.c#L2049-L2059`](https://github.com/apache/httpd/blob/1e06e9860794ce39605b79a0a787abfe084e5677/modules/proxy/mod_proxy_http.c#L2049-L2059)
   calls `ap_proxy_check_connection(..., PROXY_CHECK_CONN_EMPTY)` when a later
   request acquires an existing backend connection.
5. [`proxy_util.c#L3702-L3793`](https://github.com/apache/httpd/blob/1e06e9860794ce39605b79a0a787abfe084e5677/modules/proxy/proxy_util.c#L3702-L3793)
   implements that point-in-time check. Data already visible through the
   filter stack produces `APR_ENOTEMPTY`, logs `AH03408`, and closes the
   connection. Data that has not arrived yet is not observable by this check.
6. [`mod_proxy_http.c#L1283-L1306`](https://github.com/apache/httpd/blob/1e06e9860794ce39605b79a0a787abfe084e5677/modules/proxy/mod_proxy_http.c#L1283-L1306)
   explicitly handles simultaneous `Transfer-Encoding` and `Content-Length` by
   removing the length and marking the backend closed. The candidate fixture
   uses a numeric `Content-Length` only, so that defense is not the tested path.

## Connection-state timeline

```text
A acquires backend connection
  -> A headers parsed; numeric Content-Length is accepted
  -> HTTP input filter consumes exactly the declared count
  -> filter inserts EOS even though backend will later write more bytes
  -> mod_proxy_http releases the connection; no release-time empty check
  -> delayed A tail is not yet readable
  -> B acquires the pooled connection
  -> ap_proxy_check_connection sees empty and permits reuse
  -> B response headers are parsed and B body framing is installed
  -> delayed A tail arrives on the same TCP stream
  -> B body filter consumes the next bytes from that stream
  -> A-controlled bytes are forwarded while B request metadata remains B
```

This explains the two key controls:

- In the buffered malformed case, extra bytes are already available when B
  acquires the connection. The check returns `APR_ENOTEMPTY`, Apache logs
  `AH03408`, and the connection is closed. CI result: 0/20 contamination.
- In the asynchronous case, extra bytes are not available during that check.
  They arrive during B's body window after reuse has been permitted. CI result:
  49/50 strict contamination, with the trace showing
  `reusing backend connection`.

## Source evidence versus CI evidence

| Hypothesis | Expected result | Actual result | Evidence | Status |
|---|---|---|---|---|
| Apache completes A at the declared octet count | Malformed numeric length; direct backend emits a later tail | Direct tail begins `98 83 A0000_CANARY`; Apache inserts the matching EOS | Stage 1 and `http_filters.c#L575-L657` | PASS |
| Release performs a second pending-data safety check | Reused connection rejected if release sees pending bytes | `connection_cleanup()` has no such check; buffered data is caught only at later acquisition | `proxy_util.c#L1644-L1695` | FAIL for this hypothesis |
| Acquisition checks currently visible pending bytes | Buffered extra bytes produce `AH03408` | 0/20 contamination and `AH03408` in trace | Stage 2 buffered case; `proxy_util.c#L3702-L3793` | PASS |
| Acquisition sees bytes that arrive later | Delayed tail is rejected | 49/50 contamination in delayed async case | Stage 2 shared async case | FAIL for this safety hypothesis |
| Pool reuse is required | Disable reuse or use separate backends | 0/20 with `disablereuse=On`; 0/20 with separate backend ports | Stage 1/2 controls | PASS |

## RFC and implementation assessment

[RFC 9112 section 6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)
defines a valid `Content-Length` value as the expected body length in octets.
It requires a proxy to close on a syntactically invalid response length and
warns against treating extra data as another response because of cache
poisoning risk. The fixture's numeric value is syntactically valid but wrong
for the bytes eventually written, so the invalid-syntax rule is not a direct
match.

The evidence therefore supports an interaction, not a claim that Apache must
accept arbitrary backend framing:

- Backend/application behavior is a confirmed prerequisite: it declares fewer
  octets than it eventually writes.
- Apache correctly stops the current body at the declared boundary, and its
  existing point-in-time check rejects already-buffered extra data.
- Apache nevertheless reuses the connection when extra data is delayed past
  the check, and the next request's body filter consumes it.
- The observable cross-request transfer is therefore an Apache-side response
  isolation failure under a malformed/delayed backend condition, but ownership
  and reportability still require maintainer review because the backend has
  violated HTTP framing first.

## Root-cause confidence

- **Mechanics:** high confidence. Source control flow and differential CI
  results explain the positive and all four negative controls.
- **Apache involvement:** high confidence. Reuse-disabled and separate-backend
  controls remove the effect; Apache trace records reuse and body forwarding.
- **Classification:** high confidence that the backend response is malformed;
  medium confidence that Apache will classify delayed reuse as a security
  defect rather than a consequence of an invalid origin response.
- **Generality:** low-to-medium confidence. Only Apache 2.4.69, one runtime,
  Rack 3.2.5, Thin, and the tested proxy configuration were exercised.

## Interpretation and limitations

**Result: LIKELY Apache-side response-isolation defect in an interaction with a
confirmed backend framing violation.** It is not accurate to call this purely
an Apache-independent application bug: Apache delivers A bytes under B's
response. It is also not justified to call it a general Apache vulnerability
independent of backend behavior.

The source review does not establish that ordinary tenant input in a normal
Rack/Thin deployment can create the required delayed malformed response. That
question is answered in
[`NATURAL_DEPLOYMENT_VALIDATION.md`](NATURAL_DEPLOYMENT_VALIDATION.md).

## Next action

Do not add more payload variants. The highest-value follow-up is an
independent GitHub Actions reproduction using a legitimately slow/streaming
application response but **no research-only victim-delay helper**, while
retaining a normal B response. A positive result would strengthen Apache
ownership and realistic reachability; another negative result would support
reporting the narrower, prerequisite-heavy isolation finding.
