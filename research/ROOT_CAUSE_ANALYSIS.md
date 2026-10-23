# Root-cause analysis

## Hypothesis

Apache `mod_proxy_http` can reuse one backend TCP connection for unrelated
frontend requests. If an application emits a response with a character-count
`Content-Length` but later streams the remaining wire bytes, those bytes may
remain available when Apache assigns the pooled connection to the next request.
The question is whether Apache safely rejects/discards that state or forwards
it as the next tenant's response body.

## Test configuration

The public fixture is Rack 3.2.5 behind Thin and Apache HTTP Server 2.4.69.
Tenant A requests an ordinary missing URL containing percent-encoded UTF-8
path data. Rack/Thin declares 146 bytes but later emits a tail beginning with
`98 83 A0000_CANARY`. Tenant B requests `/victim` with a separate request ID.
Apache uses one shared `ProxyPass` worker unless a case explicitly selects
separate backend ports.

## Confirmed observations

1. Direct Thin emits the malformed/delayed response. This is an application
   framing defect reachable through an ordinary URL request; no backend process
   control is given to the synthetic attacker.
2. With reuse enabled, the strict classifier saw attacker canary bytes in a
   complete B response in 78/100 iterations (Stage 1) and 49/50 iterations
   (Stage 2). B's status, tenant header, and request ID remained B's in the
   positive sample, while its body began with A's canary.
3. Apache's trace includes `reusing backend connection` followed by
   `start body send`, and Apache's `%{proxy-source-port}n` note correlated
   78/100 or 49/50 A/B pairs with the same backend source port.
4. With `disablereuse=On` and a healthy fast B response, all controls were
   clean and no A/B pair shared the backend source port.

## Root-cause boundary

The directly demonstrated boundary is Apache's proxy connection-management
and response-body handling path: `mod_proxy` acquires/reuses the backend
connection and `mod_proxy_http` sends the response body to the current
frontend request. The trace proves Apache is the component that places bytes
from the pooled backend stream into B's response.

The backend prerequisite is also real and material. Stage 2 showed:

- separate A/B backend ports: 0/20 contamination;
- correct byte length: 0/20;
- malformed but buffered body: 0/20, with Apache forcibly closing a reusable
  connection that was not empty;
- fast victim response: 0/20.

Therefore the current finding is not “any arbitrary extra backend bytes always
poison Apache.” It is a narrower interaction involving a shared reusable
backend, a malformed length, delayed asynchronous streaming, and a victim
body timing window.

## Relevant implementation and protocol references

- Apache `mod_proxy_http` source: [2.4.x `mod_proxy_http.c`](https://github.com/apache/httpd/blob/2.4.x/modules/proxy/mod_proxy_http.c)
- Apache proxy connection utilities: [2.4.x `proxy_util.c`](https://github.com/apache/httpd/blob/2.4.x/modules/proxy/proxy_util.c)
- Apache request note documenting `proxy-source-port`: [mod_proxy_http2 request notes](https://httpd.apache.org/docs/2.4/mod/mod_proxy_http2.html#request-notes)
- HTTP/1.1 message framing: [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)

RFC 9112 frames a response body using the message framing rules and does not
make an extra byte after a complete response a safe second tenant response.
The observed forwarding behavior should therefore be reviewed by Apache
maintainers as a possible proxy isolation flaw, while the malformed backend
precondition must be disclosed prominently.

## Expected versus actual

Expected: after Apache consumes the declared A body, it should not expose the
remaining A bytes as B's response body; a malformed or non-empty reusable
connection should be discarded or produce an isolated error.

Actual: under the async delayed fixture, Apache reused the backend connection
and B received A-controlled body bytes while retaining B response metadata.

## PASS / FAIL / INCONCLUSIVE

- Apache/body-isolation failure: **PASS**.
- Apache is the only component needed to observe the cross-tenant transfer in
  the tested deployment: **PASS**.
- Generality to all backends/configurations: **INCONCLUSIVE**.
- High/XSS/CVE classification: **INCONCLUSIVE / not established**.

## Limitations

- Only Apache 2.4.69, Rack 3.2.5, Thin, and the tested Linux runner were used.
- The attacker must be able to cause a backend response with this malformed
  framing and delayed streaming pattern; ordinary tenant control over a
  response is deployment-specific.
- The public evidence does not test production data, caching, HTTP/2, TLS
  backends, alternate MPMs, or other proxy modules.
- No upstream Apache source was modified.

## Next recommended action

Send a private, non-public security report to Apache's security process with
the positive run, controls, trace excerpt, exact prerequisites, and mitigations
for maintainer ownership review. Do not claim that every Rack/Thin deployment
or every tenant can reach the High/XSS path.

## Validation record

| Hypothesis | Test configuration | Expected result | Actual result | Evidence | Status | Interpretation | Limitation | Next action |
|---|---|---|---|---|---|---|---|---|
| Apache pooling crosses the tenant response boundary | One shared `ProxyPass`, reuse enabled, A then B | B receives only B bytes | B retained B metadata but received A canary bytes | Runs 39950101256 and 39950603922 | PASS | Apache proxy path is implicated | Backend framing is malformed | Private maintainer review |
| A malformed response is safely isolated | Reuse disabled, separate backends, correct length, buffered body | No A bytes in B | All controls clean; buffered case forcibly closed | Run 39950603922 | PASS | Controls narrow the mechanism | Not a universal version survey | Validate against maintainer test matrix |
| This is a general Apache bug independent of backend behavior | Alternate backend/framing/version matrix | Same result broadly | Not tested | None | INCONCLUSIVE | Ownership is plausible but generality is unknown | Only one backend family/version | Apache should reproduce with its own harness |
