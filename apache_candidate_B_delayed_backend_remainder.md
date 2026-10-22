# Apache HTTP Server Candidate B
## Delayed bytes after response framing -> pooled backend connection reuse

Status: **high-priority hypothesis / not yet reproduced**

Scope constraints:

- Public source analysis only
- Localhost-only testing
- Self-built malformed backend/client only
- Validate Apache HTTP Server **2.4.69** and current **trunk**
- Do not test third-party production servers
- Do not scan the Internet
- Do not publish a PoC while unconfirmed
- Do not send disclosure automatically

Promotion criteria: only treat this as a security finding if all are true:

1. Reproduces on 2.4.69 or current trunk
2. Has a localhost-only PoC
3. Has clear security impact
4. Is not a duplicate
5. Identifies a concrete invariant failure
6. Has a control case proving causality

---

# Executive summary

This candidate targets a framing/reuse race in `mod_proxy_http`.

Source behavior:

1. Apache parses a backend response.
2. `ap_http_filter` determines the response body has reached EOS according to HTTP framing (`Content-Length`, chunked framing, no-body status, etc.).
3. `mod_proxy_http` treats the response as complete.
4. The backend connection may be released to the connection pool immediately.
5. On the next request, Apache calls:

```c
ap_proxy_check_connection(..., PROXY_CHECK_CONN_EMPTY)
```

before reusing the pooled backend connection.

This protects against bytes already waiting on the connection.

The candidate asks whether a malicious/malformed backend can exploit the timing gap:

```text
response A reaches declared EOS
        |
Apache releases backend connection to pool
        |
next request acquires connection
        |
empty-check sees no bytes
        |
backend sends delayed excess bytes from response A
        |
bytes are parsed in request B's response context
```

Potential consequence if genuinely controllable:

- response queue poisoning
- cross-request response desynchronization
- cache poisoning
- response mix-up between frontend requests

This is **not yet reproduced**.

Also note the exploitability requirement:

A backend with total control of request B can simply send a malicious response to B, so that is not an interesting security boundary. To be security-relevant, demonstrate that an attacker who controls only response A, or only data reflected into response A, can influence the response processing of request B.

---

# Core invariant

Expected invariant:

```text
When Apache considers backend response A complete and returns
its TCP connection to the pool, there must be no possibility for
bytes belonging to A to later be interpreted as response B.
```

Equivalent framing invariant:

```text
message ownership:
bytes[A] must remain bound to response A

pool ownership:
connection released after A must be clean for B
```

Potential violation:

```text
Content-Length / chunk parser emits EOS
        ->
connection considered reusable
        ->
empty check performed at time T1
        ->
late bytes arrive at T2 > T1
        ->
same socket now belongs to request B
        ->
late bytes parsed as B's status/header/body
```

---

# Relevant source

Stable release:

- Apache HTTP Server 2.4.69, released 2026-10-01
- https://httpd.apache.org/download.cgi

2.4.69 source:

- https://raw.githubusercontent.com/apache/httpd/2.4.69/modules/proxy/mod_proxy_http.c

Current trunk:

- https://raw.githubusercontent.com/apache/httpd/trunk/modules/proxy/mod_proxy_http.c

Official mod_proxy_http documentation:

- https://httpd.apache.org/docs/current/mod/mod_proxy_http.html

---

# Important source path 1: EOS -> immediate release

In the 2.4.x response body loop, after lifetime-transforming buckets:

```c
if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(pass_bb))) {
    finish = TRUE;

    for (e = APR_BRIGADE_FIRST(pass_bb); ... ) {
        apr_bucket_setaside(e, r->pool);
    }

    apr_brigade_cleanup(bb);

    ap_proxy_release_connection(backend->worker->s->scheme,
                                backend, r->server);

    req->backend = NULL;
}
```

Current trunk has the same fundamental behavior, with:

```c
proxy_run_detach_backend(r, backend);
ap_proxy_release_connection(...);
req->backend = NULL;
```

The explicit reason in the source is to release the backend as soon as the response is known complete.

This makes correctness of the "EOS means the socket is clean" invariant critical.

---

# Important source path 2: pooled connection empty check

Before use, 2.4.x performs:

```c
if (ap_proxy_check_connection(scheme, backend, r->server, 1,
                              PROXY_CHECK_CONN_EMPTY)
        && ap_proxy_connect_backend(...)) {
    ...
}
```

The official documentation also describes a known backend keepalive race:

`proxy-initial-not-pooled` avoids a case where the backend closes a pooled connection after the proxy's connection check but before the proxy sends request data.

That documented race is about connection closure, not this delayed-data hypothesis, but it proves that:

```text
connection check
        ->
subsequent socket state change
```

is already a recognized timing boundary in this subsystem.

Do not confuse the two.

---

# Threat model required for a real finding

Weak / insufficient model:

```text
fully malicious backend server
```

Why insufficient:

A fully malicious backend receiving request B can simply send an arbitrary response to B.

Stronger model to prove:

```text
attacker controls only response A
or
attacker controls an application-level reflection primitive in response A
or
one backend request context can emit excess bytes but has no authority over request B
```

Then:

```text
A's bytes
cross request boundary
into B
```

This can become a genuine proxy isolation failure.

The localhost fake backend is useful to prove parser/reuse mechanics, but after that the impact analysis must narrow the attacker capability.

---

# Local-only topology

Use only loopback:

```text
client A ----\
              \
               > 127.0.0.1:18080 Apache
              /            |
client B ----/             |
                           v
                     127.0.0.1:19080
                       fake backend
```

The backend must:

- accept one TCP connection
- support at least two sequential HTTP requests on that same connection
- timestamp every recv/send
- expose the server-side file descriptor / connection ID in logs
- deliberately delay selected bytes

The test is invalid if request B uses a new backend TCP connection.

---

# First experiment: Content-Length + delayed second status line

Conceptual backend timeline:

```text
T0: receive request A

T1: send:
    HTTP/1.1 200 OK
    Content-Length: 2

    OK

T2: Apache should consider A complete

T3: wait DELAY

T4: receive request B on the same backend TCP connection

T5: send bytes intentionally attributed to the malformed remainder of A
    and observe how Apache parses them
```

Do not start by sending the delayed bytes before B exists; Apache's `PROXY_CHECK_CONN_EMPTY` may detect them.

The candidate specifically tests the race window.

Suggested delay sweep:

```text
0 ms
1 ms
5 ms
10 ms
25 ms
50 ms
100 ms
250 ms
500 ms
1000 ms
```

But timing alone is not proof.

Log exact ordering:

```text
backend A final byte sent
Apache A client response completes
backend B request first byte received
malformed delayed bytes sent
backend legitimate B response sent
client B bytes received
```

---

# Critical variants

## B1 - excess complete response after CL

Response A:

```http
HTTP/1.1 200 OK
Content-Length: 2

OK
```

Later, on same socket:

```http
HTTP/1.1 200 OK
X-Poison: from-A
Content-Length: 6

POISON
```

Then separately send the legitimate response intended for B.

Observe whether B receives:

```text
POISON response
```

instead of the legitimate B response.

This is only a transport/parser mechanics test.

Do not yet call it exploitable.

---

## B2 - partial delayed status line

Split the excess response:

```text
"HTTP/1.1 200 "
delay
"OK\r\n..."
```

Purpose:

test whether any parser preread / brigade state interacts with reuse.

Record whether:

- socket empty check notices first fragment
- connection is closed
- parser consumes the fragment as B
- B receives 502
- B receives mixed status/header data

---

## B3 - delayed header prefix

After A's declared body:

```text
HTTP/1.1 200 OK\r\n
X-A:
```

Then wait until B is on the connection.

Send remainder.

This tests incremental response parser state separately from whole-response injection.

---

## B4 - chunked equivalent

A:

```http
HTTP/1.1 200 OK
Transfer-Encoding: chunked

2
OK
0

```

Then delayed excess response bytes.

Compare CL and chunked behavior.

If only one framing mode is affected, identify why.

---

## B5 - bodyless responses

Test separately:

```text
HEAD
204
304
```

These paths can release a backend connection without reading a normal response body.

They are particularly valuable because the parser may consider the response complete immediately after headers.

Current trunk explicitly releases the backend immediately on the `header only` path.

Questions:

```text
Can bytes arriving after the header-only completion be inherited by B?
Does PROXY_CHECK_CONN_EMPTY always catch them?
```

---

# Control matrix

Every positive observation must include controls.

## Control 1 - `Connection: close`

Response A:

```http
Connection: close
```

Expected:

```text
no backend reuse
no cross-request contamination
```

If the effect survives, the hypothesis is wrong.

---

## Control 2 - `proxy-nokeepalive`

Set:

```apache
SetEnv proxy-nokeepalive 1
```

Expected:

```text
new backend connection per request
effect disappears
```

---

## Control 3 - send excess bytes before pool checkout

Send delayed bytes early enough that they are already waiting when B tries to reuse the socket.

Expected if `PROXY_CHECK_CONN_EMPTY` works:

```text
Apache rejects/closes the dirty pooled connection
```

This proves the timing dimension.

---

## Control 4 - no excess bytes

Two normal sequential backend responses.

Expected:

```text
A -> client A
B -> client B
```

---

## Control 5 - new backend connection for B

Force backend connection A closed.

Expected:

```text
no contamination
```

---

# Determinism requirement

Do not accept a result based only on a race that appears once.

A valid reproduction should show a repeatable window.

Target:

```text
>= 100 local iterations per delay point
```

Record:

```text
same-connection reuse count
dirty-connection detected count
B poisoned count
B 502 count
B normal count
```

If the result depends on scheduler noise, instrument the fake backend so the sequence is synchronized by observed request events rather than arbitrary sleep alone.

Preferred synchronization:

```text
1. complete A
2. wait until fake backend receives first byte of request B
3. inject delayed A remainder
4. then send legitimate B response
```

This tests whether the clean check occurred before the late bytes became readable.

---

# Apache configuration controls

Keep the initial configuration minimal.

Example shape:

```apache
Listen 127.0.0.1:18080

LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so

ProxyPass        / http://127.0.0.1:19080/
ProxyPassReverse / http://127.0.0.1:19080/
```

Use an MPM/configuration that allows backend connection pooling.

Record:

```text
httpd -V
httpd -M
httpd -v
MPM
APR/APR-util versions
ProxyPass parameters
worker reuse settings
```

Do not expose the listener externally.

---

# Instrumentation

Backend log should include:

```text
monotonic timestamp
connection id
request number
bytes received
bytes sent
send phase
delay phase
socket close
```

Client should save raw response bytes, not only curl's parsed output.

Useful local evidence:

```text
hexdump
tcpdump on lo only
Apache trace log
backend event log
client event log
```

If using packet capture:

```text
capture only loopback and only the selected local ports
```

The goal is to prove exact byte ownership.

---

# Source questions to answer

While running the harness, trace:

```text
ap_get_brigade()
ap_http_filter
EOS generation
ap_proxy_buckets_lifetime_transform()
ap_proxy_release_connection()
ap_proxy_check_connection()
PROXY_CHECK_CONN_EMPTY
ap_proxy_connect_backend()
```

Key question:

> Does EOS mean "the framed message is complete", or does any layer additionally verify that the socket contains no bytes beyond the framed message before returning it to the pool?

If no final cleanliness verification exists at release time, the timing hypothesis remains plausible.

Also inspect where `PROXY_CHECK_CONN_EMPTY` is implemented and whether it is:

- nonblocking `recv(MSG_PEEK)` equivalent
- poll-based
- APR bucket/filter aware
- executed before or after pool ownership changes
- able to detect bytes buffered above the socket layer

---

# Duplicate checking

Search historical Apache issues before escalation.

Known nearby security families:

- CVE-2022-37436
  - malicious backend -> response header truncation / splitting
- CVE-2024-42516
  - HTTP response splitting
- CVE-2026-63718
  - mod_proxy_uwsgi Transfer-Encoding response smuggling
- Bug 70122
  - 1xx interim status-line response splitting

Apache security history:

https://httpd.apache.org/security/vulnerabilities_24.html

Search terms:

```text
mod_proxy_http response smuggling
backend keepalive extra bytes
pooled backend response
Content-Length extra bytes
backend dirty connection
PROXY_CHECK_CONN_EMPTY
ap_proxy_check_connection response
late backend bytes
response queue poisoning
```

Also inspect:

```text
CHANGES
2.4.x commit history
Bugzilla
dev@httpd archives
security advisories
```

Do not assume "no CVE found" means non-duplicate.

---

# Security-impact proof

A fake malicious backend proves only the transport invariant.

For a real finding, narrow the capability.

Good impact model:

```text
request A reaches an application endpoint where attacker-controlled
data can cause bytes beyond the backend's declared response framing
to be emitted

request B is unrelated and not attacker-controlled

Apache reuses the same backend connection

A's excess bytes become B's response
```

High-value observable consequences:

```text
B receives attacker-chosen status
B receives attacker-chosen headers
B receives attacker-chosen body
cache stores A-controlled response under B's key
security headers for B are replaced/bypassed
```

Weak/non-security outcomes:

```text
backend connection closes
B gets 502
Apache logs protocol error
only the malicious backend's own next response is affected
```

---

# Stop conditions

Stop/park if any are true:

- 2.4.69 and trunk always reject/close the connection
- dirty bytes are always detected before reuse
- cross-request effect requires full control of the backend after receiving B
- effect is only a backend-generated 502/connection reset
- no real isolation boundary can be constructed
- behavior is a duplicate of an existing issue
- result depends on unrealistic TCP behavior that cannot occur with the HTTP parser path

---

# Promotion criteria

Promote only when:

```text
[ ] current 2.4.69 or trunk reproduces
[ ] same backend TCP connection proven
[ ] local-only deterministic PoC
[ ] control with keepalive disabled kills the effect
[ ] dirty-before-check control is detected
[ ] exact timing/invariant identified
[ ] attacker capability narrower than "owns backend"
[ ] request B is outside attacker's normal authority
[ ] concrete security consequence
[ ] duplicate search complete
```

Potential final invariant statement if confirmed:

```text
mod_proxy_http releases a backend connection for reuse as soon as
HTTP framing emits EOS, but connection cleanliness is checked only
when a later request acquires the pooled connection.

Bytes belonging to the previous response can arrive after that
check and be interpreted in the next request's response context,
violating response ownership across pooled requests.
```

Do not use this wording until runtime evidence proves it.

---

# Current assessment

```text
Source plausibility:       high
2.4.69 runtime evidence:   none yet
trunk runtime evidence:    none yet
control case:              designed, not executed
security impact:           hypothetical
duplicate status:          no exact duplicate established
overall:                   HIGH-PRIORITY HYPOTHESIS
```

Recommended order:

1. prove same-socket reuse
2. prove `PROXY_CHECK_CONN_EMPTY` detects bytes already waiting
3. synchronize delayed bytes after B checkout
4. observe B parsing
5. repeat with CL / chunked / HEAD / 204 / 304
6. only then work on exploitability / realistic attacker capability

The decisive question is:

> Can bytes that semantically belong to backend response A arrive after Apache has reassigned that pooled TCP connection to request B and be parsed as B's response?

If no, park it immediately.
