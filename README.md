# oidc-lint — OAuth/OIDC misconfig scanner + passkey readiness

**What:** One-shot linter: discovery fetch → static checks (PKCE, nonce, implicit, scopes, introspection/revocation/JWKS) → headers sanity → passkey (WebAuthn) readiness heuristics.

**Usage**
```bash
pipx install .       # or: pip install .
oidc-lint https://accounts.example.com --json-out report.json
cat report.json | jq .
```

**MVP Checks**
- HTTPS everywhere (issuer/endpoints), same-origin sanity
- Discovery fields presence (auth/token/userinfo/jwks)
- PKCE support (`S256`), warn on `plain`
- Response types (`code` must exist; warn on implicit/hybrid)
- `id_token_signing_alg_values_supported` sanity (warn on only HS*)
- JWKS reachable & valid keys (kid/kty/use/alg)
- Introspection/Revocation endpoint presence
- Scope creep hints (unusual scopes)
- Security headers at authorization endpoint (CSP, X-Frame-Options)
- Passkey readiness (find WebAuthn hints on landing page, AASA/assetlinks)

**Output**: JSON with `issues[] {id, sev, msg}` and `meta` (discovery/JWKS snippets).
