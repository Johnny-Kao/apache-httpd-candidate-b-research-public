# Apache Candidate B research handoff

## Objective

Determine whether Apache HTTP Server has a reportable cross-tenant response
isolation flaw, and whether the impact can be directly classified High/CVE.
All Apache execution must remain on public GitHub Actions; do not run Apache
locally.

## Confirmed state

- Public repo: `Johnny-Kao/apache-httpd-candidate-b-research-public`
- Local clone: `/tmp/apache-candidate-b.xT6FeF`
- Latest commit: `60b48f5`
- Apache/Thin runtime is executed only on public GitHub-hosted Actions.
- Evidence file: `research/evidence/rack-thin-apache-2026-10-23.md`

## Confirmed real result

Corrected workflow [39950101256](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39950101256)
tested Apache 2.4.69 with Rack 3.2.5 and Thin:

- Ordinary tenant-A URL input reaches Rack/Thin.
- The strict direct check declares 146 bytes and emits a delayed tail later;
  the tail starts with `98 83 A0000_CANARY`.
- Apache connection reuse enabled: strict tenant-B body contamination `78/100`.
- `disablereuse=On` with a healthy victim: `0/20` contamination and `20/20`
  complete clean responses.
- This is a real chain: A input → malformed/delayed backend response → pooled
  Apache connection → unrelated B body receives A-controlled bytes.

## Stage 2 root-cause result

Workflow [39950603922](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39950603922)
showed the following prerequisites:

- shared backend pool: required;
- malformed byte/character `Content-Length`: required;
- delayed asynchronous streaming: required in this fixture;
- delayed victim response window: required in this timing;
- separate backend ports and correct framing: clean controls.

Apache trace explicitly recorded `reusing backend connection` and body-send
events. See `research/ROOT_CAUSE_ANALYSIS.md`.

## Application-impact result

Workflow [39952446877](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39952446877)
showed `21/30` strict contamination in a synthetic JSON victim, but zero
contaminated JSON parses and zero changed synthetic security decisions.

## Unresolved High-impact path

The real Rack/Thin HTML marker variant is still negative:

- Thin directly emits `98 83<script>A_CONTROLLED_MARKER</script>...` as a
  delayed tail.
- Apache test: HTML marker in B body was not observed across the tested delay
  pairs.
- The victim response remained valid HTML; no browser execution was proven.
- A separate synthetic backend harness did prove header contamination and
  browser DOM execution, but that harness supplies a stronger queued full
  response and is not proof that ordinary Rack/Thin tenant input reaches it.
- Do not claim real XSS, sensitive-data disclosure, RCE, or High severity yet.

## Important failed approaches

- Full second `HTTP/1.1` response tails are accepted by Thin but were not
  delivered to B; Apache treats that path as non-reusable/error-prone.
- A single A/B timing pair can miss the real contamination. The repeat loop is
  required; the corrected 100-iteration test produced `78/100` strict hits.
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

## Reports and next step

Required reports now exist:

- `research/VALIDATION_MATRIX.md`
- `research/ROOT_CAUSE_ANALYSIS.md`
- `research/IMPACT_ASSESSMENT.md`
- `research/REPRODUCIBILITY_REPORT.md`

Recommended next action is private Apache security triage using the proven
response-isolation evidence and explicit malformed/delayed-backend
prerequisite. Do not publicly file an Apache vulnerability issue or claim a
CVE/High rating without maintainer confirmation.
