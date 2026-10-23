# Natural-deployment validation

## Hypothesis

The response-isolation failure may occur in a realistic shared-backend
multi-tenant deployment without the custom victim-delay timing helper used by
the original fixture.

## Test configuration and controls

All Apache/Thin runtime tests were executed on public GitHub-hosted runners.
The fixture uses only synthetic tenants and markers. The relevant source is
[`research/rack_thin_fixture/config.ru`](rack_thin_fixture/config.ru):

- `AsyncBody` deliberately emits only the declared prefix and schedules the
  remaining bytes later on Thin's event loop.
- `DelayedVictimBody` deliberately delays B's body and creates the favorable
  overlap window.
- `RACK_THIN_FAST_VICTIM=1` returns B through a normal one-element Rack array,
  removing the custom victim delay.
- `buffered_malformed` returns a normal buffered Rack array, removing the
  custom asynchronous A body.

The Stage 2 matrix already contains the necessary naturalness controls;
repeating them would add little information.

## Results

| Hypothesis / case | Expected result | Actual result | Evidence | Status |
|---|---|---|---|---|
| A delayed malformed tail contaminates B with original timing helper | Strict A provenance in a complete B response | 49/50 contamination; same backend source-port correlation in 49/50 | [CI 39950603922](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39950603922), `shared_async_delayed` | PASS |
| Removing custom B delay preserves the effect | Positive contamination with a normal B body | 0/20 contamination; all B responses clean | Same run, `shared_async_fast_victim` | FAIL |
| Normal buffered Rack response with malformed length is sufficient | Positive contamination without custom async A body | 0/20; Apache logged `AH03408` and closed the non-empty reusable connection | Same run, `shared_buffered_malformed_delayed` | FAIL |
| Correct framing is sufficient | A bytes in B despite correct length | 0/20; direct delayed tail absent | Same run, `shared_correct_length_delayed` | FAIL |
| Separate backend workers still cross the boundary | A bytes reach B across distinct backend ports | 0/20 | Same run, `separate_backend_async_delayed` | FAIL |
| Ordinary Rack/Thin HTML input reaches B's browser DOM | A marker in B HTML and then browser DOM | Marker absent in all tested delay pairs; browser gate not reached | [CI 39951536767](https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/39951536767) | FAIL |

## Fixture versus realistic deployment

The positive path has a real Rack/Thin URL-to-response component—the A
request reaches the Rack file-serving path—but the response is then wrapped in
`AsyncBody` with a wrong numeric length. The positive victim path is also
wrapped in `DelayedVictimBody`. These are legitimate test programs, but they
are not ordinary behavior of an unmodified Rack application.

The fast-victim and buffered cases are stronger naturalness controls because
they use ordinary Rack array bodies. Both are negative. The real HTML probe
also remained negative, so the evidence does not show that a normal tenant can
turn the raw corruption into a browser document or accepted application data.

## Required prerequisites observed

The tested positive requires all of the following:

1. A shared reusable Apache backend connection/pool.
2. A backend response with a syntactically valid but too-small `Content-Length`.
3. Extra A bytes delayed until after Apache's empty-connection check.
4. A victim body window long enough for those bytes to arrive before B ends.

The fourth item is the significant limitation. In this implementation and
fixture, removing the explicit B delay eliminated the effect in 20/20
iterations. This does not prove that no naturally slow application can create a
similar window, but it does mean ordinary Rack/Thin behavior was not shown to
do so.

## Interpretation

**Result: NOT SUPPORTED for a positive result in the tested realistic/no-helper
deployment.** The constrained mechanism is reproducible, but current evidence
supports only a deployment with an engineered or otherwise unusually favorable
victim timing window. A real application that legitimately streams slowly
could still be a possible trigger, but that remains unconfirmed.

This does not discard the source-level isolation observation. It means the
exploit prerequisites must be stated precisely and the 78/100 and 49/50 rates
must not be generalized to ordinary deployments.

## Limitations

- One Apache version (2.4.69), Thin, Rack 3.2.5, proxy configuration, and
  runner environment were tested.
- No production application or non-synthetic tenant data was used.
- The negative fast-victim sample is 20 iterations, not an exhaustive timing
  proof.
- No claim is made about every streaming framework or Apache MPM.

## Next action

Only one further experiment is justified: replace `DelayedVictimBody` with a
legitimate slow/streaming application response that has no research-only timer,
keep B's response otherwise normal, and repeat enough times to establish byte
provenance. A positive complete B response containing A bytes would change the
realistic-deployment conclusion; another clean result should stop this branch.
