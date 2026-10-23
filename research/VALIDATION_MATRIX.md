# Candidate B validation matrix

Status: evidence package for coordinated disclosure research. This is not a
CVE assignment or a final severity decision.

## Scope and controls

- Runtime: GitHub-hosted Ubuntu runners only. No Apache or Thin runtime was
  executed locally.
- Components: Apache HTTP Server 2.4.69, Rack 3.2.5, Thin, and the checked-in
  synthetic fixture.
- Data: tenant labels, request IDs, canaries, `VICTIM-OWN`, and
  `B_SYNTHETIC_SECRET` only.
- Apache backend reuse was measured with the documented
  `%{proxy-source-port}n` request note, not the unavailable Thin `REMOTE_PORT`.

## T01–T07 — evidence correction

| Test | Hypothesis / expected result | Actual result | Evidence | Status | Interpretation / limitation / next action |
|---|---|---|---|---|---|
| T01 direct framing | Rack/Thin emits a response whose declared length differs from wire bytes; direct tail begins with the known canary. | Declared 146, body 146 before the client boundary, tail begins `98 83 A0000_CANARY`. | [Stage 1 run 39950101256](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39950101256), commit `5fa8b80` | PASS | Direct backend behavior is reproducible. It does not by itself prove an Apache issue. |
| T02 strict body provenance | Only the A canary in a complete B response counts as contamination. | Classifier distinguishes attacker bytes, clean B, request-ID/status mismatch, truncation, errors, and unknown body mismatch. | `research/test_rack_thin_validation.py` | PASS | Generic `body != expected` is no longer sufficient. |
| T03 request correlation | B must carry its own request ID and B tenant header. | Positive sample has status 200, `x-probe-id=probe-0000-victim`, `x-tenant=B`, body starts `98 83 A0000_CA`. | Stage 1 run 39950101256 | PASS | This is body contamination, not a swapped response header. |
| T04 reuse-enabled baseline | Shared pooled backend connection permits A tail to enter B. | 78/100 attacker-byte contamination; 22/100 clean; 0 classified HTTP errors. | Stage 1 run 39950101256 | PASS | Reproduces the real chain with strict provenance. |
| T05 backend connection trace | Positive requests correlate with Apache backend connection reuse. | 78/100 A/B request pairs share Apache backend source port; trace includes `reusing backend connection`. | Stage 1 run 39950101256; Apache `%{proxy-source-port}n` docs | PASS | Source-port correlation is per request; a pair need not share a port for every iteration to prove the byte provenance. |
| T06 reuse-disabled control | Disabling reuse prevents A tail from reaching B. | 20/20 complete clean `VICTIM-OWN`; 0/20 attacker bytes; 0/20 shared backend source ports. | Stage 1 run 39950101256 | PASS | A delayed-victim variant separately produced truncation under `Connection: close`; that was retained as a limitation, not counted as a negative result. |
| T07 reproducibility | The strict baseline and control repeat on a fresh runner. | Fresh run reproduced both the positive baseline and clean control. | Stage 1 run 39950101256 | PASS | Public logs contain synthetic data only. |

## T08–T15 — root-cause isolation

| Test | Hypothesis / expected result | Actual result | Evidence | Status | Interpretation / limitation / next action |
|---|---|---|---|---|---|
| T08 direct vs proxy | Direct Thin shows malformed framing; only Apache proxy creates cross-tenant transfer. | Direct tail present; shared Apache case 49/50 contamination. | [Stage 2 run 39950603922](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39950603922), commit `eac3a6a` | PASS | Apache is the component crossing the request boundary in this deployment. |
| T09 shared backend | Shared backend pool is required. | Shared async delayed: 49/50 contamination; separate A/B Thin backends: 0/20, all clean. | Stage 2 run 39950603922 | PASS | Requires a deployment where tenant traffic reaches one reusable backend worker/pool. |
| T10 correct length | Malformed Content-Length is required. | Correct byte length: direct tail absent; 0/20 contamination, 20/20 clean. | Stage 2 run 39950603922 | PASS | Length/framing defect is necessary in this fixture. |
| T11 buffered malformed | A malformed length alone should reproduce the issue if async streaming is irrelevant. | Buffered malformed body had a direct extra tail but 0/20 contamination; Apache logged `AH03408 ... reusable backend connection is not empty: forcibly closed`. | Stage 2 run 39950603922 | PASS | The observed path needs the delayed event-loop streaming window, not merely extra bytes in one buffered write. |
| T12 victim delay | A response-body timing window is required. | Same malformed async A with fast B victim: 0/20, all clean. | Stage 2 run 39950603922 | PASS | Delay is a demonstrated prerequisite for this implementation/timing. |
| T13 Apache trace | Apache should show pooled connection acquisition/reuse and body forwarding. | Trace shows `reusing backend connection`, `start body send`, `release connection`, and `end body send`. | Stage 2 run 39950603922 | PASS | Trace identifies `mod_proxy`/`mod_proxy_http` connection-management and body-send paths; it is not a source-level proof of intended ownership. |
| T14 versions | Results must state versions and assumptions. | Apache 2.4.69, Rack 3.2.5, Thin, Ubuntu GitHub runner; synthetic Host-based tenants; one shared backend unless stated otherwise. | Stage 2 workflow and logs | PASS | Other Apache versions, MPMs, front-end protocols, and backend servers remain untested. |
| T15 limitation check | Errors and truncations must not be counted as contamination. | Strict classifier keeps them separate; delayed-victim/close interaction is recorded as a limitation. | `research/test_rack_thin_validation.py` | PASS | Continue with impact tests only from complete, provenance-confirmed responses. |

## T16–T20 — application impact

| Test | Hypothesis / expected result | Actual result | Evidence | Status | Interpretation / limitation / next action |
|---|---|---|---|---|---|
| T16 valid accepted victim response | Contamination may be a complete response accepted by a victim application. | Contaminated B body starts with invalid UTF-8 `98 83`; it was not valid JSON. | [Stage 3 run 39952446877](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39952446877), commit `60b48f5` | FAIL (impact not demonstrated) | Body isolation failure is proven, but application acceptance is not. |
| T17 structured JSON integrity | A synthetic JSON victim should remain parseable or show explicit corruption. | 21/30 contamination, 0 contaminated samples parseable; 9 clean B samples parseable. | Stage 3 run 39952446877 | PASS | Clean parsing is not an impact claim; contaminated parsing remained zero. |
| T18 synthetic security decision | A contaminated JSON response changes `allowed=false`. | 0 accepted decision changes. | Stage 3 run 39952446877 | PASS (no change) | No application-level authorization impact was demonstrated. |
| T19 reproducible raw impact | Complete B responses can carry attacker bytes repeatedly. | 49/50 and 78/100 positive runs provide reproducibility. | Stage 1/2 runs | PASS | This is the currently established security-relevant impact. |
| T20 confidentiality | A canary can disclose a synthetic B secret. | No B secret was present in any contaminated body; no valid parsed B response was produced. | Stage 3 run 39952446877 | FAIL (disclosure not demonstrated) | Do not claim secret disclosure or High severity. |

## T21–T26 — higher-impact assessment

| Test | Hypothesis / expected result | Actual result | Evidence | Status | Interpretation / limitation / next action |
|---|---|---|---|---|---|
| T21 real Rack/Thin HTML bytes | Ordinary Rack URL input can place a harmless script marker in B HTML. | All tested delay pairs returned the intact B HTML; marker absent. | [Real Rack/Thin impact run 39951536767](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39951536767) | FAIL (not demonstrated) | No real tenant-input HTML path. |
| T22 real browser DOM | The real marker reaches a B-origin browser DOM. | Gate was not reached because T21 was negative; browser positive false. | Run 39951536767 | INCONCLUSIVE | No browser XSS claim. |
| T23 synthetic header integrity | A fully queued backend response can alter B response headers. | Synthetic backend inserted `X-A-Controlled: A_ONLY` into B response with reuse enabled; clean B with reuse disabled. | [Synthetic high-impact run 39951084313](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39951084313) | PASS (synthetic prerequisite) | Demonstrates Apache consequence under a stronger backend condition, not ordinary Rack tenant reachability. |
| T24 synthetic browser DOM | A fully queued HTML response can execute in B origin. | Chromium DOM title became `A_CONTROLLED_CANARY`; reuse-disabled control rendered `B_SAFE`. | Run 39951084313 | PASS (synthetic prerequisite) | High-like path is possible only after the stronger response-queue condition is supplied. |
| T25 cache integrity | Contamination changes a cache entry or cache key. | No cache module or cache poisoning test was run. | None | INCONCLUSIVE | Requires an isolated cache fixture and separate authorization before testing. |
| T26 browser/confidentiality boundary | Real tenant input yields XSS or secret disclosure. | Not demonstrated; JSON and real HTML tests were negative for the relevant impact. | Runs 39951536767 and 39952446877 | FAIL (impact not demonstrated) | Stop High escalation until a direct real-application path exists. |

## T27–T32 — reporting readiness

| Test | Hypothesis / expected result | Actual result | Evidence | Status | Interpretation / limitation / next action |
|---|---|---|---|---|---|
| T27 component ownership | Apache proxy reuse/body handling is involved. | Confirmed by Apache trace and reuse-disabled differential. | Stage 2 run 39950603922 | PASS | Submit privately for Apache maintainer ownership review; do not modify upstream. |
| T28 mitigation | `disablereuse=On`, separate backends, correct byte length, or removing delayed streaming prevents contamination. | All four controls were clean in the relevant cases. | Stage 1/2 runs | PASS | Include mitigations as deployment workarounds, not as proof of a fix. |
| T29 regression behavior | Strict classifier remains reproducible after harness changes. | Stage 1 baseline/control and Stage 2 cases passed after classifier correction. | Runs 39950101256 and 39950603922 | PASS | Preserve these runs as immutable evidence. |
| T30 evidence package | An independent reviewer can reproduce the positive and controls. | Public repo contains workflows, scripts, fixture, commit IDs, and run logs. | This repository and run links | PASS | Logs are public and synthetic only; keep any production details private. |
| T31 CVSS/severity | Demonstrated impact supports a final High score. | No valid JSON decision change, B secret disclosure, real HTML marker, or real browser DOM was shown. | Stage 3/4 runs | FAIL (High not supported) | Treat as a security-relevant response isolation candidate; do not self-assign CVE/High. |
| T32 coordinated disclosure | A private Apache security report is warranted. | The Apache-specific candidate is reproducible, but maintainer ownership/severity remains to be confirmed. | [Apache security reporting page](https://httpd.apache.org/security_report.html) | INCONCLUSIVE pending reviewer decision | Prepare a private report with this evidence and explicitly state the malformed/delayed backend prerequisite. |
