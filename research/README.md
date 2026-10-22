# Apache HTTP Server Candidate B

This directory contains a localhost-only harness for the delayed backend
remainder hypothesis documented in `apache_candidate_B_delayed_backend_remainder.md`.

The harness models a multi-tenant backend. The positive case gives the
attacker only tenant A's `attacker_input` value; tenant B is a separate
frontend client with a fixed request and fixed legitimate response. The
backend emits A's delayed remainder from that A input, then emits B's fixed
response. This proves the proposed cross-tenant ownership failure if Apache
reuses the socket. It is still a boundary model: a production report must
explain how an ordinary tenant-A application response can produce the
malformed remainder without granting the attacker backend-process control.

## Local run

Build Apache with proxy support, then run:

```sh
python3 research/test_candidate_b.py \
  --httpd /path/to/httpd \
  --server-root /path/to/apache-install
```

The backend and proxy bind only to `127.0.0.1`. The test records raw client
bytes and backend events under a temporary directory and fails if request B is
served over a different backend connection.

## GitHub-only trigger validation

The public workflow runs the harness on Apache 2.4.69 and current trunk. The
successful run `39871258803` is the current evidence snapshot:

- The synthetic Candidate B backend reproduced the cross-tenant mechanics on
  both Apache versions, with 100/100 positive iterations and one reused
  backend connection.
- The unpatched Collabora `proxy.php` response-length regression produced real
  extra response bytes, but the full Apache/PHP path returned independent A/B
  responses.
- The published LuminalShine #194 two-response pattern was tested with delays
  from 0 through 100 ms. Apache returned 502/503 or closed the path; B never
  received the A-side `404` response.
- The published cpp-httplib GET-body desynchronization pattern reached the
  backend only as `/index.html` and `/victim`; Apache did not forward the GET
  body as a second backend request in this reverse-proxy path.
- The Go `net/http` CONNECT and late-`ResponseWriter` patterns likewise did
  not cross the tenant boundary. Apache rejected CONNECT with 400, and the
  late-write test returned `VICTIM-OWN` to B.
- A new candidate is the old `gin-contrib/timeout` v0.0.1 pattern: a normal
  request exceeds a timeout, the middleware sends a 408, and the original
  handler goroutine later writes to the same `ResponseWriter`. The CI fixture
  is source-equivalent to that published control flow but uses only the Go
  standard library so dependency resolution cannot hide the wire result.

These are useful negative controls, not proof that the synthetic mechanism is
impossible. The current conclusion remains: Apache mechanics are observed, but
the source-equivalent timeout candidate still has to demonstrate an A-only
remainder reaching B before calling this an Apache security finding.
