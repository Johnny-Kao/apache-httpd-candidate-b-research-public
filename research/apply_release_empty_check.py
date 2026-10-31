#!/usr/bin/env python3
"""Apply a release-specific experimental check without replacing upstream sources."""
from pathlib import Path
import sys

source = Path(sys.argv[1])
code = source.read_text()
anchor = """                    proxy_run_detach_backend(r, backend);
                    ap_proxy_release_connection("""
if code.count(anchor) != 1:
    raise SystemExit(f"Expected one EOS release anchor, found {code.count(anchor)}")
replacement = """                    /* Detect already-pending bytes before pooling. This check
                     * cannot detect bytes arriving after it returns.
                     */
                    if (!backend->close) {
                        (void)ap_proxy_check_connection(backend->worker->s->scheme,
                                                        backend, r->server, 1,
                                                        PROXY_CHECK_CONN_EMPTY);
                    }
                    proxy_run_detach_backend(r, backend);
                    ap_proxy_release_connection("""
source.write_text(code.replace(anchor, replacement))
