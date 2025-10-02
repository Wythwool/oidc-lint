from __future__ import annotations
from typing import Any, Dict, List, Tuple
from .net import Client

def _sev(ok: bool, id: str, msg: str, level: str="HIGH") -> List[Dict[str,str]]:
    return [] if ok else [{"id": id, "sev": level, "msg": msg}]

def _https(u: str) -> bool:
    return isinstance(u,str) and u.lower().startswith("https://")

def run_oidc_checks(cli: Client, disc: Dict[str, Any], base_host: str) -> List[Dict[str,str]]:
    issues: List[Dict[str,str]] = []
    # required endpoints
    required = ["issuer","authorization_endpoint","token_endpoint","jwks_uri"]
    for k in required:
        if not disc.get(k):
            issues.append({"id":f"MISSING_{k.upper()}","sev":"HIGH","msg":f"{k} is missing in discovery"})
    # https only
    for k in ["issuer","authorization_endpoint","token_endpoint","jwks_uri","userinfo_endpoint"]:
        v = disc.get(k)
        issues += _sev(_https(v), f"HTTPS_{k.upper()}", f"{k} should be https", "HIGH")
    # same-origin-ish sanity
    for k in ["authorization_endpoint","token_endpoint","jwks_uri"]:
        v = disc.get(k) or ""
        if isinstance(v,str) and base_host not in v:
            issues.append({"id":f"CROSS_ORIGIN_{k.upper()}","sev":"MED","msg":f"{k} is hosted on different host: {v}"})
    # PKCE
    ccm = disc.get("code_challenge_methods_supported") or []
    if "S256" not in ccm:
        issues.append({"id":"PKCE_S256_MISSING","sev":"HIGH","msg":"PKCE S256 not advertised"})
    if "plain" in ccm:
        issues.append({"id":"PKCE_PLAIN_PRESENT","sev":"MED","msg":"PKCE 'plain' allowed; discourage"})
    # response types
    rts = disc.get("response_types_supported") or []
    if not any("code" in x for x in rts):
        issues.append({"id":"CODE_FLOW_MISSING","sev":"HIGH","msg":"Authorization Code flow not advertised"})
    if any("token" in x for x in rts):
        issues.append({"id":"IMPLICIT_ENABLED","sev":"MED","msg":"Implicit/hybrid response types enabled (token/id_token)"})
    # id_token algs
    algs = disc.get("id_token_signing_alg_values_supported") or []
    if algs and all(x.startswith("HS") for x in algs):
        issues.append({"id":"HMAC_ONLY_IDTOKEN","sev":"HIGH","msg":"Only HS* id_token algs; prefer RS*/ES*/EdDSA"})
    # userinfo
    if not disc.get("userinfo_endpoint"):
        issues.append({"id":"USERINFO_MISSING","sev":"LOW","msg":"userinfo endpoint missing"})
    # introspection/revocation
    if not disc.get("introspection_endpoint"):
        issues.append({"id":"INTROSPECTION_MISSING","sev":"LOW","msg":"introspection endpoint not advertised"})
    if not disc.get("revocation_endpoint"):
        issues.append({"id":"REVOCATION_MISSING","sev":"LOW","msg":"revocation endpoint not advertised"})
    # scopes
    scopes = disc.get("scopes_supported") or []
    unusual = [s for s in scopes if s.lower() in ("admin","root","*","all")]
    if unusual:
        issues.append({"id":"SCOPE_CREEP","sev":"MED","msg":f"unusual scopes present: {', '.join(unusual)}"})
    # authorization endpoint headers
    auth = disc.get("authorization_endpoint")
    if isinstance(auth,str):
        code, hdrs, err = cli.head(auth)
        if err:
            issues.append({"id":"AUTH_ENDPOINT_HEAD_FAIL","sev":"LOW","msg":f"head failed: {err}"})
        else:
            csp = hdrs.get("content-security-policy") or ""
            xfo = hdrs.get("x-frame-options") or ""
            if not csp: issues.append({"id":"CSP_MISSING","sev":"LOW","msg":"CSP header missing on auth endpoint"})
            if not xfo: issues.append({"id":"XFO_MISSING","sev":"LOW","msg":"X-Frame-Options missing on auth endpoint"})
    return issues
