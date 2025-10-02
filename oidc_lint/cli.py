from __future__ import annotations
import argparse, json, sys, re, urllib.parse, os, time
from typing import Any, Dict, List
from .net import Client
from .checks_oidc import run_oidc_checks
from .checks_passkey import run_passkey_checks

def main() -> int:
    ap = argparse.ArgumentParser(description="oidc-lint — OAuth/OIDC misconfig scanner + passkey readiness")
    ap.add_argument("url", help="Issuer URL or app base/login URL")
    ap.add_argument("--json-out", help="Write JSON report to path")
    ap.add_argument("--timeout", type=float, default=7.0, help="HTTP timeout seconds")
    ap.add_argument("--no-passkey", action="store_true", help="Skip passkey heuristics")
    args = ap.parse_args()

    cli = Client(timeout=args.timeout)

    url = args.url.strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https","http"):
        print("[!] URL must start with http/https", file=sys.stderr); return 2

    started = time.time()
    report: Dict[str, Any] = {"target": url, "issues": [], "meta": {}, "time": None}

    # OIDC well-known guess
    issuer_guess = None
    if url.endswith("/.well-known/openid-configuration"):
        issuer_guess = url.rsplit("/.well-known/openid-configuration",1)[0]
    else:
        issuer_guess = f"{parsed.scheme}://{parsed.netloc}"

    disc_url = issuer_guess.rstrip("/") + "/.well-known/openid-configuration"
    disc, disc_resp = cli.get_json(disc_url)

    if not disc:
        report["issues"].append({"id":"DISCOVERY_UNREACHABLE","sev":"HIGH","msg":f"Cannot fetch discovery: {disc_resp}"})
    else:
        report["meta"]["discovery_url"] = disc_url
        report["meta"]["issuer"] = disc.get("issuer")
        report["meta"]["authorization_endpoint"] = disc.get("authorization_endpoint")
        report["meta"]["token_endpoint"] = disc.get("token_endpoint")
        report["meta"]["jwks_uri"] = disc.get("jwks_uri")

        report["issues"].extend(run_oidc_checks(cli, disc, base_host=parsed.netloc))

        # JWKS peek
        jwks_url = disc.get("jwks_uri")
        if isinstance(jwks_url, str):
            jwks, jwks_resp = cli.get_json(jwks_url)
            if jwks:
                report["meta"]["jwks_keys"] = jwks.get("keys", [])[:3]
            else:
                report["issues"].append({"id":"JWKS_UNREACHABLE","sev":"HIGH","msg":f"JWKS not reachable: {jwks_resp}"})
        else:
            report["issues"].append({"id":"JWKS_MISSING","sev":"HIGH","msg":"jwks_uri missing in discovery"})

    if not args.no_passkey:
        report["issues"].extend(run_passkey_checks(cli, url))

    report["time"] = round(time.time()-started,3)

    if args.json_out:
        with open(args.json_out,"w",encoding="utf-8") as f:
            json.dump(report,f,ensure_ascii=False,indent=2)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
