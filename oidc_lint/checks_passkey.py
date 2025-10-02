from __future__ import annotations
from typing import List, Dict, Tuple
import urllib.parse
from .net import Client

def run_passkey_checks(cli: Client, url: str) -> List[Dict[str,str]]:
    issues: List[Dict[str,str]] = []
    # We don't simulate WebAuthn ceremony; we check readiness hints.
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    html, err, hdrs = cli.get_text(base)
    if err:
        issues.append({"id":"PASSKEY_FETCH_FAIL","sev":"LOW","msg":f"landing fetch failed: {err}"})
        return issues
    hints = 0
    if "PublicKeyCredential" in html or "navigator.credentials.create" in html:
        hints += 1
    # mobile app binding files
    aasa, e1, _ = cli.get_text(base+"/.well-known/apple-app-site-association")
    if not e1 and aasa.strip(): hints += 1
    al, e2, _ = cli.get_text(base+"/.well-known/assetlinks.json")
    if not e2 and al.strip(): hints += 1
    if hints == 0:
        issues.append({"id":"PASSKEY_NOT_READY","sev":"INFO","msg":"No obvious WebAuthn/passkey hints found"})
    else:
        issues.append({"id":"PASSKEY_HINTS_PRESENT","sev":"INFO","msg":f"Passkey/WebAuthn hints: {hints}"})
    return issues
