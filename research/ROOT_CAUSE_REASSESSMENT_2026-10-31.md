# Apache httpd / Rack–Thin response contamination: root-cause reassessment

Date: 2026-10-31. Status: **source-level cause verified; version-controlled end-to-end CI comparison pending**.

## First incorrect state: Rack response framing

The fixture pins Rack 3.2.5 and calls `Rack::Files` with a decoded UTF-8 path. Rack 3.2.5's `Rack::Files#fail` computes its error response `Content-Length` with `body.size`, i.e. characters rather than wire octets. This is the already-known **CVE-2026-34831**, fixed by `body.bytesize` in **Rack 3.2.6** (released 2026-04-01). This defect predates our October Apache experiments.

- Vulnerable source: https://github.com/rack/rack/blob/v3.2.5/lib/rack/files.rb
- Fixed source: https://github.com/rack/rack/blob/v3.2.6/lib/rack/files.rb
- Advisory: https://github.com/rack/rack/security/advisories/GHSA-q2ww-5357-x388

## Additional research-only prerequisites

The fixture in `research/rack_thin_fixture/config.ru` is not an ordinary Rack response:

- `Utf8PathInfo` explicitly coerces the decoded path to UTF-8.
- `AsyncBody` writes only the declared (too-short) body prefix immediately, then emits excess bytes **0.25 s later**.
- `DelayedVictimBody` delays B's real body **0.50 s**. The ordinary synchronous B-body control did not reproduce the contamination (0/20).

Thus an invalid length is necessary for these tests, but **not sufficient** to infer that an ordinary production Rack application exhibits the 49/50 rate.

## Apache side of the observed chain

In Apache 2.4.69 `modules/http/http_filters.c`, `ap_http_filter()` in `BODY_LENGTH` mode stops at the numeric length and inserts EOS when `remaining == 0`. `mod_proxy_http.c` then releases the connection. `mod_proxy_http.c` uses `ap_proxy_check_connection(..., PROXY_CHECK_CONN_EMPTY)` on acquisition; `proxy_util.c` invokes `ap_check_pipeline()` and closes when bytes are already visible.

When A's tail arrives after that point-in-time check and during B's intentionally delayed body, Apache can consume A's bytes as part of B's response body. The backend has already violated the declared HTTP framing. There is no reliable observation of bytes that have **not yet been transmitted**; rechecking merely changes timing.

See: `research/SOURCE_LEVEL_ROOT_CAUSE.md` and `HANDOFF.md`.

## Why the earlier experimental Apache patch is not a fix

Branch `research/release-time-empty-check` added another `ap_proxy_check_connection` at release time. This cannot identify a future-delayed extra tail. The paired Stage 2 run https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/41179745432 measured contamination 43/50 for stock Apache and 21/50 with the patch, but **clean responses only 7/50 vs 8/50**, while the patched run produced 21 incomplete-header classifications. This is **not** a demonstrated fix.

## Cause-targeted solution and verification

The concrete origin error is fixed in upstream Rack 3.2.6 (and newer). Existing supported deployments should upgrade Rack (and ensure any custom streaming body obeys its declared framing). Apache's `disablereuse=On` is a deployment-level mitigation with a keep-alive performance tradeoff, not a general source fix.

The new branch `research/rack-framing-root-cause` compares Rack 3.2.5 and 3.2.6 against **unmodified Apache 2.4.69**, including direct backend tail, cross-request contamination, clean B responses, and negative controls. Run: https://github.com/Johnny-Kao/apache-httpd-candidate-b-research-public/actions/runs/41180822566 . Only CI evidence can establish the end-to-end outcome.

**Upstream PR decision:** no Apache PR on the release-time check; Rack's initial framing cause is already patched upstream. A separate Apache hardening change would need an independently justified invariant, reproducible regression test, and evidence of acceptable impact on correct backends.
