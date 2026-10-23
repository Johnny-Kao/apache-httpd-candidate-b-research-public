# Apache Candidate B research handoff

## Objective

Determine whether Apache HTTP Server has a reportable cross-tenant response
isolation flaw, and whether the impact can be directly classified High/CVE.
All Apache execution must remain on public GitHub Actions; do not run Apache
locally.

## Confirmed state

- Public repo: `Johnny-Kao/apache-httpd-candidate-b-research-public`
- Local clone: `/tmp/apache-candidate-b.xT6FeF`
- Worktree is clean; latest commit: `d92890b`
- No Actions are running. Candidate B and response-split runs were cancelled.
- Evidence file: `research/evidence/rack-thin-apache-2026-10-23.md`

## Confirmed real result

Workflow [39947213045](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39947213045)
successfully tested Apache 2.4.69 with Rack 3.2.5 and Thin:

- Ordinary tenant-A URL input reaches Rack/Thin.
- Backend declares 125 bytes but sends 285 bytes later.
- Apache connection reuse enabled: tenant-B body contamination `77/100`.
- `disablereuse=On`: `0/20` contamination.
- This is a real chain: A input → malformed/delayed backend response → pooled
  Apache connection → unrelated B body receives A-controlled bytes.

## Unresolved High-impact path

The real HTML marker variant is still negative:

- Thin directly emits `98 83<script>A_CONTROLLED_MARKER</script>...` as a
  delayed tail.
- Apache test: HTML marker in B body `0/100`.
- The victim response remained valid HTML; no browser execution was proven.
- Do not claim XSS, sensitive-data disclosure, header poisoning, RCE, or High
  severity yet.

## Important failed approaches

- Full second `HTTP/1.1` response tails are accepted by Thin but were not
  delivered to B; Apache treats that path as non-reusable/error-prone.
- A single A/B timing pair missed the real contamination. The repeat loop is
  required; the 100-iteration test produced the real `77/100` result.
- HTML tests with oversized URLs produced Thin `400 Bad Request`; do not use
  those as Apache negative results.
- HTML marker alignment must be checked against the direct delayed-tail prefix
  before interpreting Apache results.

## Constraints to preserve

- Use GitHub Actions only for Apache/Thin runtime testing.
- Keep one intended workflow running; push path triggers can start unrelated
  Candidate B and response-split runs, so cancel those immediately or use
  manual dispatch.
- Preserve the reuse-disabled control.
- Separate raw body contamination from browser/XSS impact.
- Do not use arbitrary Linux commands or destructive payloads; server-side
  execution would require a separate execution sink and is not implied by
  response-body forwarding.

## Next recommended step

Before changing the payload again, inspect Apache's proxy trace and the exact
victim-body parse for the HTML variant. If the same pooled connection carries
the raw `98 83` bytes only when B's body is a short text response, test a
minimal valid HTML victim whose declared body length is just large enough to
contain a harmless script marker, while keeping the URL below Thin's limit.
Any positive result must include raw B bytes, browser DOM/title evidence, and
the `disablereuse=On` negative control in one GitHub Actions run.
