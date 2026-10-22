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
