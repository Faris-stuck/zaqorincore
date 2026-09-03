# F-007: CSP allows script from `https://esm.sh` CDN — supply-chain + SRI risk

| Field | Value |
|---|---|
| Severity | Medium |
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| CVSS-like | 5.0 (AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N) |
| Location | `server/src/zaqorincore_server/security.py:30-39`, `webui/index.html:185-191` |
| Status | Open |

## Description

The bundled WebUI loads React 18 from a public CDN:

```html
<!-- webui/index.html -->
<script type="importmap">
{
  "imports": {
    "react": "https://esm.sh/react@18.3.1",
    "react-dom/client": "https://esm.sh/react-dom@18.3.1/client"
  }
}
</script>
```

The server CSP reflects this:

```python
# server/src/zaqorincore_server/security.py
_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://esm.sh; "        # <-- CDN allow-listed
    "style-src 'self' 'unsafe-inline'; "        # <-- inline style allowed
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)
```

There is **no `subresource-integrity` attribute** on the importmap and no `integrity=`
attribute on the script tag. The CDN is not pinned by hash; it is pinned by version
string (`react@18.3.1`) and the CDN can serve any code under the `esm.sh` origin.

## Impact

* **CDN compromise** — if `esm.sh` (or a transitive dependency it serves) is compromised,
  an attacker gets arbitrary script execution in the WebUI every time an operator opens
  the console. The browser will load whatever bytes are at the URL, including a fresh
  malicious payload.
* **Subresource takeovers** — `esm.sh` aggregates thousands of third-party npm
  packages; one of those packages being compromised (or a typo-squat being resolved) is
  sufficient to backdoor the WebUI.
* **No SRI** — even with the version pinned, the integrity attribute is absent, so the
  browser has no way to detect tampering at the byte level.
* **`'unsafe-inline'` for styles** — weakens the CSP. A successful XSS in a downstream
  rendered HTML element (e.g. via React's `dangerouslySetInnerHTML` if it ever appears)
  is harder to contain.

## POC sketch

Network-position attacker (or compromised CDN) replaces the bytes served at
`https://esm.sh/react@18.3.1` with a JavaScript payload that exfiltrates the operator's
`X-API-Key` from `localStorage` (if cached) and POSTs it to an attacker-controlled host.
Browser has no way to detect the swap because the URL is the same and no SRI attribute
is present.

## Remediation sketch

1. **Vendor React locally** under `webui/static/vendor/` and update the importmap to
   `"./static/vendor/react.js"`. The current `security.py` docstring already calls this
   out as the planned path: *"Once the React bundle is vendored locally (post-1.0),
   the CSP can be tightened to ``default-src 'self'``."*
2. Add `integrity="sha384-..."` to any future CDN-hosted script reference.
4. Tighten `style-src` to drop `'unsafe-inline'` once the inline `<style>` in
   `index.html` is moved to a stylesheet.