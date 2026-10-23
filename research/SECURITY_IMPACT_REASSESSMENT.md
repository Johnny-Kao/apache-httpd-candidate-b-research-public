# Security-impact reassessment

## Hypothesis

Cross-tenant response-body contamination may become an application-level
integrity or confidentiality impact, such as valid JSON manipulation, browser
HTML execution, header confusion, cache poisoning, or secret disclosure.

## Confirmed impact

The strict byte-provenance classifier confirms a narrower impact:

- A-controlled bytes entered a complete B response in 78/100 baseline
  iterations and 49/50 shared async Stage 2 iterations.
- B's status, request ID, and tenant metadata remained associated with B.
- `disablereuse=On`, separate backend ports, correct byte length, buffered
  malformed response, and fast victim controls were clean in the relevant
  cases.
- The direct A response and Apache traces establish the delayed tail and
  pooled-connection reuse; this is not a generic error or response swap.

Evidence: [Stage 1](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39950101256)
and [Stage 2](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39950603922).

## Impact hypotheses and actual results

| Hypothesis | Expected evidence | Actual result | Status |
|---|---|---|---|
| Contaminated body remains valid victim JSON | A body containing A bytes parses as B JSON | 21/30 strict contamination, but 0 contaminated bodies parsed; 9 clean samples parsed | FAIL |
| Contamination changes a security-sensitive decision | A valid contaminated JSON changes synthetic `allowed=false` | 0 accepted decision changes | FAIL |
| Ordinary Rack/Thin HTML reaches B browser DOM | A marker appears in real B HTML and executes in Chromium | Real HTML marker absent; browser gate not reached | FAIL / INCONCLUSIVE |
| Queued backend response can alter B headers/DOM | A-controlled header and harmless HTML marker appear under reuse | Synthetic stronger harness produced `X-A-Controlled: A_ONLY` and DOM title `A_CONTROLLED_CANARY`; reuse-disabled control was clean | PASS only for synthetic characterization |
| Backend contamination discloses B secret | A canary or valid response reveals synthetic B secret | No contaminated valid B response and no secret disclosure | FAIL |
| Cache isolation is broken | A-controlled data changes an isolated cache entry or key | No cache fixture was run | INCONCLUSIVE |

Evidence: [Stage 3 JSON](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39952446877),
[real Rack/Thin HTML](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39951536767),
and [synthetic header/DOM characterization](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39951084313).

The final natural-streaming validation
([run 39955810018](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39955810018))
used Rack's documented Enumerable response-body path, Ruby `String#each_line`,
correct B `Content-Length`, and no victim timer. It produced 20/20 clean B
responses; the reuse-disabled control produced 10/10 clean responses. The raw
body artifact is [12503155233](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39955810018/artifacts/12503155233).

## What the synthetic high-impact harness does and does not prove

The queued-response harness proves that if the backend stream is arranged so
that A's complete queued response is available at the relevant point, Apache
can forward A-controlled header/body material under B. It also proves that a
browser can execute the resulting harmless marker in that stronger setup.

It does **not** prove that an ordinary Rack/Thin tenant can supply that queued
response shape. The real Rack/Thin HTML path did not reach the raw marker gate,
and the JSON path did not produce an accepted contaminated object. Therefore
the synthetic result is useful for impact characterization, not for a High or
XSS claim.

## Severity decision

The current evidence supports a security-relevant response-isolation candidate
with strict prerequisites. It does not support High, XSS, confidential-data
disclosure, cache poisoning, authorization bypass, RCE, or a final CVE claim.
The principal unresolved question is Apache maintainer ownership of behavior
triggered by an invalid origin response and a favorable timing window.

**Further High/XSS investigation: NOT SUPPORTED.** The highest-value natural
streaming experiment was completed and was negative. The higher-impact branch
should stop. The remaining finding is the narrower, timing- and malformed-
backend-dependent response-isolation behavior.

## Required evidence for any escalation

An escalation would require all of the following in one reproducible chain:

1. Ordinary or explicitly legitimate tenant-controlled application behavior,
   not a research-only queued-response helper.
2. A complete B response whose A-byte provenance is independently established.
3. Valid parsing or browser DOM evidence, as appropriate.
4. A concrete security consequence using only synthetic secrets and markers.
5. Controls excluding response swapping, generic errors, truncation, and
   harness timing artifacts.

## Next action

Prepare a private Apache maintainer report around the narrower confirmed
response-isolation behavior, with the malformed A framing and favorable victim
timing prerequisite stated in the title and impact section. Do not publish the
synthetic DOM result as an ordinary tenant exploit. No further High/XSS payload
variants are justified by the current evidence.
