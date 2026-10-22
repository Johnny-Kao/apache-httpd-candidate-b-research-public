# Apache HTTP Server Candidate B

This directory contains a localhost-only harness for the delayed backend
remainder hypothesis documented in `apache_candidate_B_delayed_backend_remainder.md`.

The harness is deliberately a mechanics test. A result from a fully controlled
fake backend is not, by itself, a security finding. Any positive result must
also prove same-socket reuse, repeatability, and a narrower attacker capability.

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
