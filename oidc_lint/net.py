from __future__ import annotations
import httpx, json
from typing import Tuple, Any

# keep it small and predictable
_UA = "oidc-lint/0.1 (+https://github.com/you/oidc-lint)"

class Client:
    def __init__(self, timeout: float = 7.0):
        self._timeout = timeout
        self._cli = httpx.Client(follow_redirects=True, timeout=timeout, headers={"User-Agent": _UA})
    def get_json(self, url: str) -> Tuple[Any, str]:
        try:
            r = self._cli.get(url)
            ct = r.headers.get("content-type","")
            if r.status_code//100 != 2:
                return None, f"HTTP {r.status_code}"
            try:
                return r.json(), ""
            except Exception:
                # sometimes providers serve text/json without correct header
                return json.loads(r.text), ""
        except Exception as e:
            return None, str(e)
    def get_text(self, url: str) -> Tuple[str, str, dict]:
        try:
            r = self._cli.get(url)
            if r.status_code//100 != 2: return "", f"HTTP {r.status_code}", dict(r.headers)
            return r.text, "", dict(r.headers)
        except Exception as e:
            return "", str(e), {}
    def head(self, url: str) -> Tuple[int, dict, str]:
        try:
            r = self._cli.head(url)
            return r.status_code, dict(r.headers), ""
        except Exception as e:
            return 0, {}, str(e)
