# Impact assessment

## Hypothesis

If A-controlled bytes can enter a complete B response, they may affect an
application parser, response headers, caches, browser HTML, or confidentiality
boundaries. Each consequence must be demonstrated independently.

## Demonstrated impact

The strict raw-body result is reproducible and security-relevant:

- Stage 1: 78/100 complete B responses contained an A canary; reuse-disabled
  control: 0/20.
- Stage 2: 49/50 complete B responses contained an A canary; separate backend,
  correct-length, buffered, fast-victim, and reuse-disabled controls were
  clean.
- B response status, tenant marker, and request ID remained B in the positive
  sample. The body was therefore corrupted/cross-contaminated rather than a
  simple header/request swap.

This is a response integrity and tenant-isolation failure. It can cause
victim-visible corruption, incorrect content, or application errors.

## Structured-data result

The synthetic JSON victim contained `tenant=B`, `allowed=false`, and
`B_SYNTHETIC_SECRET`.

- 21/30 iterations were strict A-byte contamination.
- 9/30 were clean B responses.
- 0 contaminated bodies parsed as JSON.
- 0 synthetic security decisions changed.
- No synthetic B secret was disclosed through an accepted response.

This means the current body corruption is not yet demonstrated to be an
application-accepted authorization or data-disclosure primitive.

## HTML and browser result

The real Rack/Thin HTML probe tried the same family of ordinary missing-URL
inputs across multiple A/B delay pairs. Every observed B response remained
the intact B HTML document; no A HTML marker appeared, so no real browser DOM
execution was established.

A separate synthetic backend probe did demonstrate the consequence Apache
would have if a complete A response were already queued behind B's request:

- B received `X-A-Controlled: A_ONLY` with reuse enabled and normal B headers
  with reuse disabled.
- Chromium's B-origin DOM had title `A_CONTROLLED_CANARY` with reuse enabled;
  the control rendered `B_SAFE`.

That synthetic result is useful for impact characterization, but it does not
close the real Rack/Thin attacker-input path. It must not be reported as real
tenant XSS.

## Header, cache, and confidentiality boundaries

- Real response-header modification: not demonstrated.
- Real cache poisoning: not tested; **INCONCLUSIVE**.
- Real browser XSS: not demonstrated.
- Real B secret disclosure: not demonstrated.
- Apache code execution/RCE: not demonstrated and not implied by body mixing.

## Severity assessment

The evidence supports treating this as a security-relevant Apache proxy
response-isolation candidate for private maintainer triage. It does not
support self-assigning High severity or a CVE yet. The strongest demonstrated
impact is cross-tenant response-body contamination under a constrained
malformed/delayed backend condition.

The synthetic header/HTML results show a possible higher-impact consequence
under a stronger backend response-queue condition, but the real application
reachability and provenance are absent. A final CVSS vector should be left to
Apache's triage unless a real accepted-data, secret-disclosure, cache, or
browser-impact chain is independently reproduced.

## Mitigations validated by the tests

- Disable backend connection reuse for the affected worker (`disablereuse=On`)
  as a containment measure.
- Isolate tenants onto separate backend pools/processes/ports.
- Ensure backend applications calculate `Content-Length` in wire bytes and do
  not asynchronously stream beyond the declared body.
- Treat a backend connection with pending bytes as non-reusable.

These are deployment mitigations, not a confirmed upstream Apache fix.

## Next recommended action

Prepare the private Apache report around the proven response-isolation flaw,
include the malformed/delayed response prerequisite, and ask maintainers to
confirm ownership and severity. Do not include the public synthetic HTML
probe as proof of real XSS.

## Validation record

| Hypothesis | Test configuration | Expected result | Actual result | Evidence | Status | Interpretation | Limitation | Next action |
|---|---|---|---|---|---|---|---|---|
| A bytes cross into a complete B response | Shared Apache worker, Rack/Thin async malformed A, delayed synthetic B | A canary appears in B body while B metadata remains B | 78/100 and 49/50 strict positives | Runs 39950101256 and 39950603922 | PASS | Response isolation is broken in this deployment | Requires malformed/delayed backend and timing window | Private Apache triage |
| Contamination is accepted as victim JSON | Synthetic B JSON with `allowed=false` and secret marker | Contaminated body parses and changes decision | 0 contaminated parses; 0 decision changes | Run 39952446877 | FAIL for this impact | Current bytes are corruption, not an accepted decision | Only one synthetic JSON shape | Do not claim authorization impact |
| Real tenant input reaches browser HTML | Real Rack/Thin HTML victim plus Chromium | A marker reaches B DOM | Marker absent; browser gate not reached | Run 39951536767 | FAIL / INCONCLUSIVE for browser | Synthetic queued-response browser impact is not real reachability | Browser tested only after raw marker gate | Stop High escalation |
