# Reproducibility report

## Environment

- Repository: `Johnny-Kao/apache-httpd-candidate-b-research-public`
- Public CI: GitHub-hosted Ubuntu runners only
- Apache: 2.4.69 built from the upstream `2.4.69` branch in CI
- Rack: 3.2.5
- Thin: installed from RubyGems in CI
- Tenant data: synthetic markers only
- Latest code commit: `60b48f5`

No Apache or Thin runtime was executed on the local workstation.

## Primary runs

| Purpose | Run | Commit | Result |
|---|---|---|---|
| Corrected strict baseline and reuse-disabled control | [39950101256](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39950101256) | `5fa8b80` | 78/100 positive; 20/20 clean control |
| Stage 2 root-cause isolation | [39950603922](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39950603922) | `eac3a6a` | All five cases completed with expected results |
| Stage 3 JSON integrity | [39952446877](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39952446877) | `60b48f5` | 21/30 contamination; 0 contaminated JSON parses/decision changes |
| Real Rack/Thin HTML/browser gate | [39951536767](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39951536767) | `eac3a6a` | Real HTML marker not observed |
| Synthetic header/HTML impact characterization | [39951084313](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39951084313) | `eac3a6a` | Header and browser DOM positive only in controlled backend harness |

## Reproduction procedure

1. Clone the public repository and inspect `HANDOFF.md` and the scripts under
   `research/`.
2. Use GitHub Actions `workflow_dispatch`; do not run Apache/Thin locally.
3. Run `Rack Thin validated contamination classifier` for the strict baseline
   and its reuse-disabled control.
4. Inspect the `direct=`, `classification=`, `samples=`,
   `apache_backend_correlation=`, `apache_trace_tail=`, and `result=` lines.
5. Run Stage 2 to compare shared/separate backends, framing modes, and timing.
6. Run Stage 3 to check synthetic JSON parsing and decision integrity.
7. Run the real Rack/Thin impact workflow only as a separate manual run; do
   not combine it with unrelated workflows.

## Independent expected observations

The positive sample has:

```text
status=200
x-tenant=B
x-probe-id=<B request id>
body prefix=98 83 41 30 30 30 ...
```

The direct A response has a declared body of 146 bytes and an additional tail
beginning `98 83 A0000_CANARY`. The reuse-disabled control has complete
`VICTIM-OWN` bodies and no attacker bytes.

## PASS / FAIL / INCONCLUSIVE summary

- Raw response isolation failure: PASS.
- Shared backend and async malformed prerequisite isolation: PASS.
- Accepted JSON/security-decision impact: not demonstrated; contaminated
  samples did not parse.
- Real HTML/browser impact: not demonstrated.
- Synthetic queued-response header/HTML impact: PASS as a characterization
  only, not as the real tenant trigger.
- Final CVE/High classification: INCONCLUSIVE and not claimed.

## Evidence and limitations

The run URLs retain the raw CI logs, including Apache trace lines. Public logs
contain only synthetic tenants, markers, and the synthetic secret string.
The test does not establish prevalence across all applications, Apache
versions, MPMs, HTTP/2, TLS, caches, or backend frameworks.

## Next recommended action

Have an independent reviewer reproduce Stage 1 and Stage 2 from the public
run links, then send the private evidence package to Apache's security process
for ownership and severity triage. Keep any non-synthetic deployment details
out of the public repository.

## Validation record

| Hypothesis | Test configuration | Expected result | Actual result | Evidence | Status | Interpretation | Limitation | Next action |
|---|---|---|---|---|---|---|---|---|
| The finding is reproducible | Fresh GitHub-hosted runner, Apache 2.4.69, Rack 3.2.5, Thin | Strict positive repeats and control stays clean | 78/100 positive; 20/20 clean control | Run 39950101256 | PASS | Baseline is independently rerunnable | Public CI only; timing-sensitive | Reproduce from run link |
| Root cause is pooled shared backend state | Five Stage 2 cases | Shared async case positive; controls negative | 49/50 positive; all four controls clean | Run 39950603922 | PASS | Prerequisites are bounded | Other versions/backends untested | Include prerequisites in report |
| Higher impact is proven | Real Rack/Thin HTML and synthetic browser probe | Real marker/DOM evidence | Synthetic harness positive; real Rack/Thin marker absent | Runs 39951084313 and 39951536767 | INCONCLUSIVE for real High | Apache consequence is characterized but real reachability is not | No production app or cache test | Do not claim High/CVE |
