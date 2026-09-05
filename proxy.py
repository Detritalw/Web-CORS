#!/usr/bin/env python3
"""CORS proxy — password-protected, origin-restricted, target-whitelisted.

Auth:    Authorization: Bearer <token>  (token in config.ini)
Targets: scheme://host:port whitelist. Redirects are followed internally
         and re-validated against the whitelist on every hop.
CORS:    Access-Control-Allow-Origin echoes Origin if allowed; otherwise
         the request is rejected. allow_all_origins=true opens it to *.
"""
import asyncio
import configparser
import ipaddress
import logging
import re
import socket
import sys
import time
from http.cookies import SimpleCookie
from collections import defaultdict
from pathlib import Path

import aiohttp
from aiohttp import web
from yarl import URL

CONFIG_PATH = Path(__file__).with_name("config.ini")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("cors-proxy")

# ---------------------------------------------------------------- config
_cfg = configparser.RawConfigParser()
if not _cfg.read(CONFIG_PATH):
    log.error("config.ini not found at %s", CONFIG_PATH)
    sys.exit(1)

LISTEN_HOST = _cfg.get("server", "listen_host", fallback="127.0.0.1")
LISTEN_PORT = _cfg.getint("server", "listen_port", fallback=8080)
AUTH_TOKEN = _cfg.get("auth", "token", fallback="")
ALLOW_ALL_ORIGINS = _cfg.getboolean("cors", "allow_all_origins", fallback=False)
ALLOWED_ORIGINS = {
    o.strip() for o in _cfg.get("cors", "allowed_origins", fallback="").split(",") if o.strip()
}
TARGETS_RAW = [t.strip() for t in _cfg.get("targets", "allow", fallback="").split(",") if t.strip()]

if not AUTH_TOKEN:
    log.error("auth.token is empty — refusing to start")
    sys.exit(1)
if not TARGETS_RAW:
    log.error("targets.allow is empty — refusing to start")
    sys.exit(1)

TARGET_RULES = []  # (scheme_re, host_re, port_re)
for entry in TARGETS_RAW:
    m = re.match(r"^(https?)://([^/:]+)(?::(\d+|\*))?$", entry)
    if not m:
        log.error("bad target entry: %r (expected scheme://host[:port])", entry)
        sys.exit(1)
    scheme, host, port = m.groups()
    host_re = ".*" if host == "*" else re.escape(host).replace(r"\*", "[^.]*")
    TARGET_RULES.append((re.escape(scheme), host_re, ".*" if port in (None, "*") else re.escape(port)))


_dns_cache: dict[str, bool] = {}
PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
              "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")
]


def host_is_private(host: str) -> bool:
    """True if host resolves to (or literally is) a private/loopback address."""
    if host in ("localhost", "*.local") or host.endswith(".local") or host.endswith(".localhost"):
        return True
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if literal:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in PRIVATE_NETS)
    if host in _dns_cache:
        return _dns_cache[host]
    try:
        infos = socket.getaddrinfo(host, None)
        private = any(
            ipaddress.ip_address(info[4][0]) in net
            for info in infos for net in PRIVATE_NETS
        )
    except (socket.gaierror, ValueError):
        private = True  # unresolvable → treat as blocked
    _dns_cache[host] = private
    return private


def target_allowed(url: str) -> bool:
    m = re.match(r"^(https?)://([^/:]+)(?::(\d+))?(/|$)", url)
    if not m:
        return False
    scheme, host, port, _rest = m.groups()
    port = port or ("443" if scheme == "https" else "80")
    if not any(
        re.fullmatch(s, scheme) and re.fullmatch(h, host) and re.fullmatch(p, port)
        for s, h, p in TARGET_RULES
    ):
        return False
    return not host_is_private(host)


# ---------------------------------------------------------------- limits
MAX_BODY_BYTES = 10 * 1024 * 1024
CLIENT_TIMEOUT = aiohttp.ClientTimeout(total=90, connect=10, sock_read=60)
MAX_REDIRECTS = 5
RATE_MAX = 120
RATE_WINDOW = 60  # seconds
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}

routes = web.RouteTableDef()
_rate: dict[str, list[float]] = defaultdict(list)


def client_ip(request: web.Request) -> str:
    # Trust X-Forwarded-For only from local reverse proxies; direct
    # clients could spoof it to dodge rate limiting.
    remote = request.remote or "unknown"
    if remote.startswith("127.") or remote == "::1":
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
    return remote


def rate_ok(ip: str) -> bool:
    now = time.time()
    bucket = _rate[ip]
    bucket[:] = [t for t in bucket if now - t < RATE_WINDOW]
    if len(bucket) >= RATE_MAX:
        return False
    bucket.append(now)
    return True


def check_auth(request: web.Request) -> bool:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        auth = auth[7:]
    # Query-token fallback keeps compatibility with iframe navigations, which
    # cannot attach an Authorization header. The service only listens locally.
    if not auth:
        auth = request.query.get("key", "")
    return auth == AUTH_TOKEN


def origin_allowed(request: web.Request) -> str | None:
    """Return the Origin to echo in ACAO, or None if not allowed."""
    origin = request.headers.get("Origin")
    if not origin:
        return None  # non-CORS request (curl etc.) — no ACAO needed
    if ALLOW_ALL_ORIGINS:
        return origin
    if origin in ALLOWED_ORIGINS:
        return origin
    return None


def cors_headers(request: web.Request, allow_methods: str | None = None) -> dict[str, str]:
    origin = origin_allowed(request)
    if origin is None:
        return {}
    if ALLOW_ALL_ORIGINS:
        h = {"Access-Control-Allow-Origin": "*"}
    else:
        h = {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
    if allow_methods:
        h["Access-Control-Allow-Methods"] = allow_methods
        h["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        h["Access-Control-Max-Age"] = "600"
    return h


def denied(request: web.Request, status: int, msg: str) -> web.Response:
    return web.json_response({"error": msg}, status=status, headers=cors_headers(request))


# ---------------------------------------------------------------- proxy core
async def forward(request: web.Request, method: str) -> web.Response:
    origin = request.headers.get("Origin")
    preflight = method == "OPTIONS"
    if not preflight:
        if not check_auth(request):
            return denied(request, 401, "unauthorized")
        if not rate_ok(client_ip(request)):
            return denied(request, 429, "rate limit exceeded")
        if origin and not origin_allowed(request):
            return denied(request, 403, f"origin not allowed: {origin}")
    else:
        # CORS preflight: browser sends no credentials, so no auth check.
        if origin and not origin_allowed(request):
            return denied(request, 403, f"origin not allowed: {origin}")
        return web.Response(status=204, headers=cors_headers(request, allow_methods="GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS"))

    raw = request.rel_url.raw_path.lstrip("/")
    # Support the browser client's query format: /?url=<encoded-target>&key=...
    # while retaining the canonical path format: /https://host/path.
    target_url = raw or request.query.get("url", "")
    if not target_url:
        return denied(request, 400, "usage: /<scheme>://host[:port]/path or /?url=<target>")

    target_url = target_url
    # tolerate callers that omit the scheme separator when encoded
    if not target_url.startswith(("http://", "https://")):
        m = re.match(r"^(https?)((?::|%3A)//.*)$", target_url, re.I)
        if not m:
            return denied(request, 400, "target must start with http:// or https://")
        target_url = m.group(1).lower() + "://" + raw.split("://", 1)[-1] if "://" in raw else target_url

    if not target_allowed(target_url):
        return denied(request, 403, "target not in whitelist")

    body = await request.read()
    if len(body) > MAX_BODY_BYTES:
        return denied(request, 413, "body too large")

    # Forward browser cookies to the upstream target. Keep proxy auth and
    # browser-origin headers private to the proxy.
    fwd_headers = {}
    for k, v in request.headers.items():
        if k.lower() in HOP_BY_HOP or k.lower() in ("authorization", "origin", "referer"):
            continue
        fwd_headers[k] = v
    if request.headers.get("Cookie"):
        fwd_headers["Cookie"] = request.headers["Cookie"]

    session: aiohttp.ClientSession = request.app["upstream_session"]
    url = target_url
    try:
        for _ in range(MAX_REDIRECTS + 1):
            async with session.request(
                method, url, data=body if method not in ("GET", "HEAD") else None,
                headers=fwd_headers, allow_redirects=False, timeout=CLIENT_TIMEOUT,
                auto_decompress=False,
            ) as resp:
                if resp.status in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location")
                    if not loc:
                        break
                    url = str(resp.url.join(URL(loc)))
                    if method in ("GET", "HEAD") and resp.status in (301, 302, 303):
                        method2 = "GET"
                    else:
                        method2 = method
                    if not target_allowed(url):
                        return denied(request, 403, f"redirect target not in whitelist: {url}")
                    method = method2
                    continue  # re-enter loop with new url (validated)
                # final response
                out_headers = cors_headers(request)
                set_cookies = []
                for k, v in resp.headers.items():
                    if k.lower() in HOP_BY_HOP or k.lower() in ("content-security-policy", "set-cookie"):
                        continue
                    if k.lower() in out_headers:
                        continue
                    out_headers[k] = v
                for cookie in resp.headers.getall("Set-Cookie", []):
                    parsed = SimpleCookie()
                    parsed.load(cookie)
                    for morsel in parsed.values():
                        morsel["domain"] = ""
                        if not morsel["path"]:
                            morsel["path"] = "/"
                        morsel["secure"] = ""
                        morsel["samesite"] = "Lax"
                        set_cookies.append(morsel.OutputString())
                data = await resp.read()
                response = web.Response(status=resp.status, body=data, headers=out_headers)
                for cookie in set_cookies:
                    response.headers.add("Set-Cookie", cookie)
                return response
        return denied(request, 502, "too many redirects")
    except aiohttp.ClientError as e:
        return denied(request, 502, f"upstream error: {e.__class__.__name__}")
    except asyncio.TimeoutError:
        return denied(request, 504, "upstream timeout")


for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
    routes.route(method, "/{tail:.*}")(lambda r, m=method: forward(r, m))


async def on_startup(app: web.Application):
    app["upstream_session"] = aiohttp.ClientSession()


async def on_cleanup(app: web.Application):
    await app["upstream_session"].close()


app = web.Application(client_max_size=MAX_BODY_BYTES)
app.add_routes(routes)
app.on_startup.append(on_startup)
app.on_cleanup.append(on_cleanup)

if __name__ == "__main__":
    log.info("listening on %s:%s", LISTEN_HOST, LISTEN_PORT)
    web.run_app(app, host=LISTEN_HOST, port=LISTEN_PORT, print=None)
