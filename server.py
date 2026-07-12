"""cloudflare-dns-mcp — a thin, scoped Cloudflare DNS tool surface as an MCP server.

Design (deliberately NOT azobo):
  - There is NO OBO to Cloudflare. CF's API has no federated-token trust anchor, so
    the user's Entra identity CANNOT propagate to the CF call (see README). Instead:
      * front door  : validate the operator's Entra bearer (attribution + authZ),
                      exactly azobo's check, MINUS the broker (nothing to mint).
      * back end    : one ACCOUNT-SCOPED Cloudflare API token (Zone:Read + DNS:Edit),
                      from the env, never per-user.
  - The credential's ceiling is the lab account (it cannot reach prod — different
    account). The SERVER adds the floor: writes (create/edit/delete) are gated to a zone
    allow-list (CFDNS_EDIT_ZONES) + per-user app roles; delete is additionally off unless
    CFDNS_ENABLE_DELETE. CFDNS_READONLY is a hard global kill-switch on top of all of that —
    when set, create/edit/delete refuse immediately, before the allow-list/role/rate checks
    even run, so it holds regardless of how those other knobs are configured.

Five primitives: search_zones, search_records, create_record, edit_record, delete_record.
"""
import os, re, json, time, threading
import httpx
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings

os.umask(0o077)

# --- Cloudflare back end (the scoped token; the ONLY CF credential) --------------
API_BASE   = os.environ.get("CFDNS_API_BASE", "https://api.cloudflare.com/client/v4").rstrip("/")
CF_TOKEN   = os.environ.get("CFDNS_API_TOKEN", "")
ACCOUNT_ID = os.environ.get("CFDNS_ACCOUNT_ID", "").strip()  # optional; token is already account-scoped
TIMEOUT    = int(os.environ.get("CFDNS_TIMEOUT", "30"))
MAX_OUT    = int(os.environ.get("CFDNS_MAX_OUTPUT_CHARS", "60000"))
MAX_PAGES  = int(os.environ.get("CFDNS_MAX_PAGES", "40"))  # safety bound on pagination (350+ zones in prod)
AUDIT      = os.environ.get("CFDNS_AUDIT_LOG", "/var/lib/cloudflare-dns-mcp/audit.log")

# Zones (names OR ids) that create_record/edit_record may touch. EMPTY = writes
# disabled entirely (read-only server). This is the artificial lock-down ON TOP of
# the token's own ceiling — widen it zone-by-zone without re-minting the token.
EDIT_ZONES = {z.strip().lower() for z in os.environ.get("CFDNS_EDIT_ZONES", "").split(",") if z.strip()}

# --- Front door (Entra bearer) — same validation as azobo, no broker -------------
PUBLIC_HOST     = os.environ.get("CFDNS_PUBLIC_HOST", "localhost")
PORT            = int(os.environ.get("CFDNS_PORT", "8783"))
TENANT          = os.environ.get("CFDNS_TENANT_ID", "").strip()
CLIENT          = os.environ.get("CFDNS_CLIENT_ID", "").strip()
# Every request's bearer is ALWAYS cryptographically verified (JWKS sig, aud, iss, exp,
# scope, client). There is NO unauthenticated mode: the fabric always carries an Entra
# token (turnstone OBO) in both lab and prod, so an unauth path would be pure liability.
AUDIENCE        = [x for x in (CLIENT, f"api://{CLIENT}", os.environ.get("CFDNS_AUDIENCE", "").strip()) if x]
REQUIRED_SCOPE  = os.environ.get("CFDNS_REQUIRED_SCOPE", "").strip()
ALLOWED_CLIENTS = [x.strip() for x in os.environ.get("CFDNS_ALLOWED_CLIENTS", "").split(",") if x.strip()]

# --- Authorization via app roles (token `roles` claim — verified to survive turnstone's
# OBO). Reads need Dns.Read OR Dns.Write; writes need Dns.Write. A validated token with no
# matching role is DENIED (no Entra assignment => no access). Role match is case-insensitive.
READ_ROLES  = {"dns.read", "dns.write"}
WRITE_ROLES = {"dns.write"}
# Optional read-scope fence (writes are already fenced by EDIT_ZONES). Empty = reads span
# every zone the account-scoped token can see.
READ_ZONES  = {z.strip().lower() for z in os.environ.get("CFDNS_READ_ZONES", "").split(",") if z.strip()}
# delete_record is destructive with no undo — disabled unless explicitly enabled.
ENABLE_DELETE = os.environ.get("CFDNS_ENABLE_DELETE", "").lower() in ("1", "true", "yes")
# Hard global kill-switch for create/edit/delete — checked BEFORE the zone allow-list, role
# check, or rate limiter, so it holds even if CFDNS_EDIT_ZONES/CFDNS_ENABLE_DELETE later drift.
READONLY = os.environ.get("CFDNS_READONLY", "").lower() in ("1", "true", "yes")
# Account-wide read: when CFDNS_READ_ZONES is unset, reads default to the EDIT_ZONES fence
# unless this is explicitly set (then reads span every zone the token can see).
ALLOW_ACCOUNT_READ = os.environ.get("CFDNS_ALLOW_ACCOUNT_READ", "").lower() in ("1", "true", "yes")
# Effective read fence: explicit READ_ZONES > EDIT_ZONES (safe default) > account-wide (opt-in => None).
_READ_FENCE = READ_ZONES if READ_ZONES else (None if ALLOW_ACCOUNT_READ else EDIT_ZONES)
# Per-operator write rate limit (create/edit/delete) — sliding 60s window keyed by oid. 0 = unlimited.
WRITE_RATE_PER_MIN = int(os.environ.get("CFDNS_WRITE_RATE_PER_MIN", "30"))

_HEXID = re.compile(r"^[0-9a-f]{32}$")
_GUID  = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_lock = threading.Lock()
_writes = {}  # oid -> [recent write timestamps], for the rate limiter

def _validate_config():
    """Fail-closed config gate — runs at IMPORT (not just __main__), so no launch path can
    serve with auth disabled or with unfilled sample placeholders still in place."""
    def _ph(v):  # reject empty, whitespace-only, or sample placeholders
        v = str(v).strip()
        return (not v) or ("<" in v) or (">" in v) or ("REPLACE" in v.upper())
    if _ph(CF_TOKEN):
        raise SystemExit("CFDNS_API_TOKEN is missing or still the sample placeholder.")
    if _ph(TENANT) or _ph(CLIENT):
        raise SystemExit("CFDNS_TENANT_ID and CFDNS_CLIENT_ID must be real values (every token is validated).")
    if not (_GUID.match(TENANT) and _GUID.match(CLIENT)):
        raise SystemExit("CFDNS_TENANT_ID and CFDNS_CLIENT_ID must be specific tenant/app GUIDs — "
                         "multi-tenant aliases (common/organizations/consumers) are refused.")
    if _ph(REQUIRED_SCOPE):
        raise SystemExit("CFDNS_REQUIRED_SCOPE is required — pin the coarse 'valid caller' scope.")
    if not ALLOWED_CLIENTS or any(_ph(c) for c in ALLOWED_CLIENTS):
        raise SystemExit("CFDNS_ALLOWED_CLIENTS is required — pin the calling client (turnstone).")
    # Accounting is a control: prove the audit log is writable at startup rather than
    # discovering it mid-mutation (writes still go to stderr if it fails later, critical=True).
    try:
        os.makedirs(os.path.dirname(AUDIT) or ".", exist_ok=True)
        with open(AUDIT, "a"):
            pass
    except Exception as e:
        raise SystemExit(f"audit log {AUDIT!r} is not writable ({type(e).__name__}) — refusing to start.")

_validate_config()

# ---------------------------------------------------------------------------------
# auth / audit
# ---------------------------------------------------------------------------------
def _bearer(ctx):
    try:
        h = ctx.request_context.request.headers.get("authorization", "") or ""
        return h[7:].strip() if h[:7].lower() == "bearer " else ""   # require the Bearer prefix
    except Exception:
        return ""

def _ident(c):
    owner = c.get("oid") or c.get("upn") or c.get("preferred_username") or "?"
    display = c.get("preferred_username") or c.get("upn") or c.get("oid") or "?"
    roles = [str(r).lower() for r in (c.get("roles") or [])]
    return (owner, display, roles)

_jwks = None
def _jwks_client():
    global _jwks
    if _jwks is None:
        from jwt import PyJWKClient
        _jwks = PyJWKClient(f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys")
    return _jwks

def _identity(bearer):
    """(owner, display, roles) ONLY after the bearer is cryptographically verified for this
    tenant+app (JWKS signature, audience, issuer, expiry, required scope, allowed client).
    Returns None on any failure — callers MUST reject. There is no unauthenticated path."""
    # Defense-in-depth: even if config validation were somehow bypassed, never authenticate
    # anyone unless the gates are actually configured.
    if not (TENANT and CLIENT and REQUIRED_SCOPE and ALLOWED_CLIENTS):
        return None
    if not bearer:
        return None
    try:
        import jwt
        key = _jwks_client().get_signing_key_from_jwt(bearer).key
        claims = jwt.decode(bearer, key, algorithms=["RS256"], audience=AUDIENCE,
                            options={"require": ["exp"], "verify_aud": True})
        if claims.get("iss", "") not in (f"https://login.microsoftonline.com/{TENANT}/v2.0",
                                          f"https://sts.windows.net/{TENANT}/"):
            return None
        if claims.get("tid") != TENANT:   # pin the exact tenant — not just an iss-shaped string
            return None
        if REQUIRED_SCOPE and REQUIRED_SCOPE not in str(claims.get("scp", "")).split():
            return None
        if ALLOWED_CLIENTS and (claims.get("azp") or claims.get("appid")) not in ALLOWED_CLIENTS:
            return None
        return _ident(claims)
    except Exception:
        return None

def _auth(ctx):
    """Returns (owner, display, roles) or None (=> emit the unauth error)."""
    return _identity(_bearer(ctx))

def _authz(roles, write):
    """App-role authorization (roles come from the verified token). Reads need
    Dns.Read|Dns.Write; writes need Dns.Write. Returns (ok, why)."""
    have = set(roles or [])
    if not (have & (WRITE_ROLES if write else READ_ROLES)):
        verb = "write (the Dns.Write app role)" if write else "read (the Dns.Read app role)"
        return False, (f"not authorized: this operation requires {verb}. Ask an admin to assign it "
                       "to you on the cloudflare-dns-mcp app in Entra.")
    return True, None

def _redact(rtype, content):
    """Keep readable values (A/AAAA/CNAME/MX/NS) in the audit, but hash secret-bearing
    TXT/SPF content so the log can't leak verification tokens / secrets."""
    if (rtype or "").upper() in ("TXT", "SPF") and content:
        import hashlib
        return "sha256:" + hashlib.sha256(content.encode()).hexdigest()[:16]
    return content

def _rate_ok(oid):
    """Sliding 60s per-operator write budget (create/edit/delete). True if under the cap."""
    if WRITE_RATE_PER_MIN <= 0:
        return True
    now = time.time()
    with _lock:
        q = [t for t in _writes.get(oid, []) if now - t < 60]
        if len(q) >= WRITE_RATE_PER_MIN:
            _writes[oid] = q
            return False
        q.append(now); _writes[oid] = q
    return True

def _audit(ident, tool, detail, ok, critical=True):
    """Append-only JSONL accounting: immutable oid + human upn + verb + target + result.
    A dropped line ALWAYS goes to stderr/journald (audit is a control) — reads included; only
    set critical=False to allow a silent drop, which nothing here does."""
    oid, who = ident[0], ident[1]
    rec = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "oid": oid, "who": who, "tool": tool, "detail": detail, "ok": bool(ok)})
    try:
        os.makedirs(os.path.dirname(AUDIT) or ".", exist_ok=True)
        with _lock, open(AUDIT, "a") as f:
            f.write(rec + "\n")
        return True
    except Exception as e:
        if critical:
            import sys
            print(f"AUDIT-WRITE-FAILED {type(e).__name__}: {rec}", file=sys.stderr, flush=True)
        return False

def _err(msg):
    return json.dumps({"error": msg})

def _out(obj):
    s = json.dumps(obj, indent=2, sort_keys=False)
    if len(s) <= MAX_OUT:
        return s
    return s[:MAX_OUT] + f"\n…[TRUNCATED at {MAX_OUT} chars — narrow your query (name/type filter or smaller limit)]"

# ---------------------------------------------------------------------------------
# Cloudflare API
# ---------------------------------------------------------------------------------
def _cf(method, path, params=None, body=None):
    """One CF API call with the scoped token. Returns (success: bool, payload: dict)."""
    headers = {"Authorization": f"Bearer {CF_TOKEN}", "Content-Type": "application/json"}
    try:
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.request(method, f"{API_BASE}{path}", headers=headers, params=params, json=body)
    except Exception as e:
        return False, {"errors": [{"message": f"transport: {type(e).__name__}: {str(e)[:160]}"}]}
    try:
        data = r.json()
    except Exception:
        return False, {"errors": [{"message": f"HTTP {r.status_code}: {r.text[:300]}"}]}
    return bool(data.get("success")), data

def _cf_errors(data):
    errs = data.get("errors") or []
    msg = "; ".join(str(e.get("message", e)) for e in errs) or "unknown Cloudflare API error"
    # Surface the common scope miss helpfully.
    if any("9109" in str(e.get("code", "")) or "Unauthorized" in str(e.get("message", "")) for e in errs):
        msg += "  [hint: the API token may be missing a permission — search_zones needs Zone:Read; edits need DNS:Edit]"
    return msg

def _paginate(path, params, per_page, item_cap):
    """Walk CF's paginated list endpoints, bounded by MAX_PAGES and item_cap."""
    items, page = [], 1
    while page <= MAX_PAGES:
        q = dict(params or {}); q.update({"page": page, "per_page": per_page})
        ok, data = _cf("GET", path, params=q)
        if not ok:
            return None, _cf_errors(data)
        batch = data.get("result") or []
        items.extend(batch)
        info = (data.get("result_info") or {})
        total_pages = info.get("total_pages") or (page if len(batch) < per_page else page + 1)
        if page >= total_pages or len(batch) < per_page or len(items) >= item_cap:
            break
        page += 1
    return items, None

def _resolve_zone(zone):
    """Accept a zone NAME or 32-hex id; return (id, name, error). A 32-hex id is trusted
    as-is (no extra call); a name is resolved via the list endpoint (works with a
    DNS:Edit token — CF returns zones you hold any permission on)."""
    z = (zone or "").strip()
    if not z:
        return None, None, "zone is required (name like 'your-zone.example' or a 32-hex zone id)"
    if _HEXID.match(z.lower()):
        ok, data = _cf("GET", f"/zones/{z.lower()}")   # resolve id -> name so allow-list + audit see the name
        if ok:
            rr = data.get("result") or {}
            return rr.get("id") or z.lower(), rr.get("name"), None
        # Unresolvable id: fail closed unless it's EXPLICITLY allow-listed by id (no blind trust).
        if z.lower() in EDIT_ZONES or z.lower() in READ_ZONES:
            return z.lower(), None, None
        return None, None, (f"zone id {z!r} could not be resolved to a name and is not explicitly "
                            "allow-listed — refusing (avoids acting on an unverified id).")
    params = {"name": z}
    if ACCOUNT_ID:
        params["account.id"] = ACCOUNT_ID
    ok, data = _cf("GET", "/zones", params=params)
    if not ok:
        return None, None, _cf_errors(data)
    res = data.get("result") or []
    if not res:
        return None, None, f"no zone named {z!r} visible to this token"
    return res[0].get("id"), res[0].get("name"), None

def _writable(zone_id, zone_name):
    if not EDIT_ZONES:
        return False, ("writes are disabled on this server (CFDNS_EDIT_ZONES is empty). "
                       "Add the zone to the allow-list to enable create/edit.")
    if (zone_id or "").lower() in EDIT_ZONES or (zone_name or "").lower() in EDIT_ZONES:
        return True, None
    return False, (f"zone {zone_name or zone_id!r} is not in the edit allow-list "
                   f"(CFDNS_EDIT_ZONES). This server may only modify: {sorted(EDIT_ZONES)}.")

def _readable(zone_id, zone_name):
    """Read fence: explicit READ_ZONES, else EDIT_ZONES, else account-wide (opt-in)."""
    if _READ_FENCE is None:
        return True, None
    if (zone_id or "").lower() in _READ_FENCE or (zone_name or "").lower() in _READ_FENCE:
        return True, None
    return False, (f"reads are restricted on this server; zone {zone_name or zone_id!r} is not permitted "
                   "(see CFDNS_READ_ZONES / CFDNS_ALLOW_ACCOUNT_READ).")

def _rec_view(r):
    return {"id": r.get("id"), "type": r.get("type"), "name": r.get("name"),
            "content": r.get("content"), "ttl": r.get("ttl"), "proxied": r.get("proxied"),
            "comment": r.get("comment"), "zone_name": r.get("zone_name")}

# ---------------------------------------------------------------------------------
# MCP
# ---------------------------------------------------------------------------------
mcp = FastMCP("cloudflare-dns",
    instructions=("Read and manage Cloudflare DNS for THIS account's zones. Five tools: "
        "search_zones (find zones by name substring — prod has 350+), search_records (list/filter "
        "records in one zone), create_record, edit_record and delete_record (writes gated to an "
        "allow-list of zones). delete_record is destructive — confirm the record_id via search_records "
        "first. Records default to proxied=false (dumb DNS). "
        "Every call is attributed to the signed-in operator; the Cloudflare call itself uses a single "
        "account-scoped token, so the boundary you'll hit is the token's permissions + the edit "
        "allow-list, not your personal identity."),
    # Stateless: no server-side session table, so a server restart never orphans a
    # client (no Mcp-Session-Id to go stale). Safe here because cfmcp is pure
    # request/response — no server->client notifications/sampling/elicitation/subscriptions.
    host="127.0.0.1", port=PORT, stateless_http=True, json_response=True, streamable_http_path="/",
    transport_security=TransportSecuritySettings(
        allowed_hosts=[PUBLIC_HOST, f"{PUBLIC_HOST}:443", f"127.0.0.1:{PORT}", f"localhost:{PORT}"],
        allowed_origins=[f"https://{PUBLIC_HOST}", f"http://127.0.0.1:{PORT}"]))


@mcp.tool()
def search_zones(ctx: Context, query: str = "", limit: int = 50) -> str:
    """Find DNS zones (domains) in this Cloudflare account. `query` is a case-insensitive
    substring matched against the zone name (e.g. 'pow3r' or '.com'); empty lists all.
    Returns id/name/status for up to `limit` matches. Requires Zone:Read on the token.
    Use this to discover the zone id/name you then pass to the record tools."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation (signature/audience/issuer/expiry)")
    owner, who, roles = ident
    az_ok, az_why = _authz(roles, write=False)
    if not az_ok:
        _audit(ident, "search_zones", {"denied": az_why}, False)
        return _err(az_why)
    limit = max(1, min(int(limit or 50), 500))
    params = {"account.id": ACCOUNT_ID} if ACCOUNT_ID else {}
    items, error = _paginate("/zones", params, per_page=50, item_cap=10_000)
    if error:
        _audit(ident, "search_zones", {"query": query}, False)
        return _err(error)
    q = (query or "").strip().lower()
    matched = [z for z in items if (not q or q in (z.get("name", "").lower()))
               and (_READ_FENCE is None or z.get("name", "").lower() in _READ_FENCE or z.get("id", "").lower() in _READ_FENCE)]
    view = [{"id": z.get("id"), "name": z.get("name"), "status": z.get("status")} for z in matched[:limit]]
    _audit(ident, "search_zones", {"query": query, "matched": len(matched)}, True)
    return _out({"count": len(matched), "shown": len(view), "zones": view})


@mcp.tool()
def search_records(ctx: Context, zone: str, query: str = "", type: str = "", limit: int = 100) -> str:
    """List/filter DNS records within ONE zone. `zone` = a zone name ('your-zone.example') or 32-hex
    zone id (from search_zones). `query` = case-insensitive substring matched against the record
    name OR content (e.g. 'xconnect' or '3.1.0'). `type` = optional exact record type filter
    (A, AAAA, CNAME, TXT, MX, …). Returns up to `limit` records. Read-only."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    owner, who, roles = ident
    az_ok, az_why = _authz(roles, write=False)
    if not az_ok:
        _audit(ident, "search_records", {"zone": zone, "denied": az_why}, False)
        return _err(az_why)
    limit = max(1, min(int(limit or 100), 1000))
    zid, zname, error = _resolve_zone(zone)
    if error:
        return _err(error)
    rd_ok, rd_why = _readable(zid, zname)
    if not rd_ok:
        _audit(ident, "search_records", {"zone": zname, "denied": rd_why}, False)
        return _err(rd_why)
    params = {}
    if type.strip():
        params["type"] = type.strip().upper()
    items, error = _paginate(f"/zones/{zid}/dns_records", params, per_page=100, item_cap=50_000)
    if error:
        _audit(ident, "search_records", {"zone": zname}, False)
        return _err(error)
    q = (query or "").strip().lower()
    def hit(r):
        return not q or q in (r.get("name", "").lower()) or q in (str(r.get("content", "")).lower())
    matched = [r for r in items if hit(r)]
    view = [_rec_view(r) for r in matched[:limit]]
    _audit(ident, "search_records", {"zone": zname, "query": query, "matched": len(matched)}, True)
    return _out({"zone": zname, "zone_id": zid, "count": len(matched), "shown": len(view), "records": view})


@mcp.tool()
def create_record(ctx: Context, zone: str, type: str, name: str, content: str,
                  ttl: int = 1, proxied: bool = False, comment: str = "") -> str:
    """Create a DNS record. `zone` = name or id (MUST be in the server's edit allow-list).
    `type` = A/AAAA/CNAME/TXT/MX/… , `name` = full record name ('xconnect.your-zone.example' or '@'),
    `content` = the value (IP, target, text). ttl=1 means automatic. proxied defaults to false
    (dumb DNS / grey-cloud). Writes are real and attributed to you."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    owner, who, roles = ident
    if READONLY:
        _audit(ident, "create_record", {"zone": zone, "name": name, "denied": "read-only mode"}, False, critical=True)
        return _err("server is in read-only mode (CFDNS_READONLY): all writes are disabled.")
    az_ok, az_why = _authz(roles, write=True)
    if not az_ok:
        _audit(ident, "create_record", {"zone": zone, "name": name, "denied": az_why}, False, critical=True)
        return _err(az_why)
    if not _rate_ok(owner):
        _audit(ident, "create_record", {"zone": zone, "name": name, "denied": "rate limit"}, False, critical=True)
        return _err(f"write rate limit exceeded ({WRITE_RATE_PER_MIN}/min) — slow down and retry.")
    zid, zname, error = _resolve_zone(zone)
    if error:
        return _err(error)
    ok, why = _writable(zid, zname)
    if not ok:
        _audit(ident, "create_record", {"zone": zname, "name": name, "denied": why}, False, critical=True)
        return _err(why)
    body = {"type": type.strip().upper(), "name": name.strip(), "content": content,
            # parse defensively (a loose client could pass the string "false" past FastMCP) —
            # only an explicit truthy string/bool proxies; default stays DNS-only.
            "ttl": int(ttl), "proxied": str(proxied).strip().lower() in ("true", "1", "yes")}
    if comment.strip():
        body["comment"] = comment.strip()
    det = {"zone": zname, "type": body["type"], "name": body["name"], "content": _redact(body["type"], content)}
    if not _audit(ident, "create_record", {**det, "phase": "intent"}, True, critical=True):
        return _err("refusing to mutate: the audit log is unwritable (accounting is a control).")
    ok, data = _cf("POST", f"/zones/{zid}/dns_records", body=body)
    _audit(ident, "create_record", {**det, "phase": "result"}, ok, critical=True)
    if not ok:
        return _err(_cf_errors(data))
    return _out({"created": _rec_view(data.get("result") or {}), "zone": zname})


@mcp.tool()
def edit_record(ctx: Context, zone: str, record_id: str, type: str = "", name: str = "",
                content: str = "", ttl: int = 0, proxied: str = "", comment: str = "") -> str:
    """Edit an existing DNS record (PATCH — only the fields you pass change). `zone` = name or id
    (MUST be in the edit allow-list); `record_id` = the record's id (from search_records). Pass any
    of type/name/content to change them; ttl>0 to change TTL (1=auto); proxied = 'true'/'false' to
    toggle; comment to set a note. Writes are attributed to you."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    owner, who, roles = ident
    if READONLY:
        _audit(ident, "edit_record", {"zone": zone, "record_id": record_id, "denied": "read-only mode"}, False, critical=True)
        return _err("server is in read-only mode (CFDNS_READONLY): all writes are disabled.")
    az_ok, az_why = _authz(roles, write=True)
    if not az_ok:
        _audit(ident, "edit_record", {"zone": zone, "record_id": record_id, "denied": az_why}, False, critical=True)
        return _err(az_why)
    if not _rate_ok(owner):
        _audit(ident, "edit_record", {"zone": zone, "record_id": record_id, "denied": "rate limit"}, False, critical=True)
        return _err(f"write rate limit exceeded ({WRITE_RATE_PER_MIN}/min) — slow down and retry.")
    if not (record_id or "").strip():
        return _err("record_id is required (get it from search_records)")
    if not _HEXID.fullmatch(record_id.strip()):
        return _err("record_id must be a 32-char hex id (get the exact id from search_records)")
    zid, zname, error = _resolve_zone(zone)
    if error:
        return _err(error)
    ok, why = _writable(zid, zname)
    if not ok:
        _audit(ident, "edit_record", {"zone": zname, "record_id": record_id, "denied": why}, False, critical=True)
        return _err(why)
    body = {}
    if type.strip():    body["type"] = type.strip().upper()
    if name.strip():    body["name"] = name.strip()
    if content.strip(): body["content"] = content
    if int(ttl or 0) > 0: body["ttl"] = int(ttl)
    if str(proxied).strip().lower() in ("true", "false"):
        body["proxied"] = (str(proxied).strip().lower() == "true")
    if comment.strip(): body["comment"] = comment.strip()
    if not body:
        return _err("nothing to change — pass at least one of type/name/content/ttl/proxied/comment")
    cok, cdata = _cf("GET", f"/zones/{zid}/dns_records/{record_id.strip()}")   # before-snapshot for reconstructable audit
    cur = (cdata.get("result") or {}) if cok else {}
    rtype = body.get("type") or cur.get("type") or ""
    det = {"zone": zname, "record_id": record_id,
           "before": {"type": cur.get("type"), "name": cur.get("name"),
                      "content": _redact(cur.get("type", ""), cur.get("content"))},
           "changes": {k: (_redact(rtype, v) if k == "content" else v) for k, v in body.items()}}
    if not _audit(ident, "edit_record", {**det, "phase": "intent"}, True, critical=True):
        return _err("refusing to mutate: the audit log is unwritable (accounting is a control).")
    ok, data = _cf("PATCH", f"/zones/{zid}/dns_records/{record_id.strip()}", body=body)
    _audit(ident, "edit_record", {**det, "phase": "result"}, ok, critical=True)
    if not ok:
        return _err(_cf_errors(data))
    return _out({"updated": _rec_view(data.get("result") or {}), "zone": zname})


@mcp.tool()
def delete_record(ctx: Context, zone: str, record_id: str) -> str:
    """Delete a DNS record by id. `zone` = name or id (MUST be in the server's edit allow-list);
    `record_id` = the record's id (from search_records). DESTRUCTIVE and final — there is no undo,
    so confirm the exact record with search_records first (delete takes an id, never a name, on
    purpose). Attributed to you."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    owner, who, roles = ident
    if READONLY:
        _audit(ident, "delete_record", {"zone": zone, "record_id": record_id, "denied": "read-only mode"}, False, critical=True)
        return _err("server is in read-only mode (CFDNS_READONLY): all writes are disabled.")
    # AuthZ for delete = the Dns.Write role (write INTENTIONALLY includes delete — by design,
    # not a missing Dns.Delete role) + the global CFDNS_ENABLE_DELETE kill-switch.
    if not ENABLE_DELETE:
        _audit(ident, "delete_record", {"zone": zone, "record_id": record_id, "denied": "delete disabled"}, False, critical=True)
        return _err("delete_record is disabled on this server (set CFDNS_ENABLE_DELETE=true to allow it).")
    az_ok, az_why = _authz(roles, write=True)
    if not az_ok:
        _audit(ident, "delete_record", {"zone": zone, "record_id": record_id, "denied": az_why}, False, critical=True)
        return _err(az_why)
    if not _rate_ok(owner):
        _audit(ident, "delete_record", {"zone": zone, "record_id": record_id, "denied": "rate limit"}, False, critical=True)
        return _err(f"write rate limit exceeded ({WRITE_RATE_PER_MIN}/min) — slow down and retry.")
    if not (record_id or "").strip():
        return _err("record_id is required (get it from search_records)")
    if not _HEXID.fullmatch(record_id.strip()):
        return _err("record_id must be a 32-char hex id (get the exact id from search_records)")
    zid, zname, error = _resolve_zone(zone)
    if error:
        return _err(error)
    ok, why = _writable(zid, zname)
    if not ok:
        _audit(ident, "delete_record", {"zone": zname, "record_id": record_id, "denied": why}, False, critical=True)
        return _err(why)
    drec_ok, drec = _cf("GET", f"/zones/{zid}/dns_records/{record_id.strip()}")   # snapshot before destroying it
    snap = (drec.get("result") or {}) if drec_ok else {}
    det = {"zone": zname, "record_id": record_id,
           "deleted_record": {"type": snap.get("type"), "name": snap.get("name"),
                              "content": _redact(snap.get("type", ""), snap.get("content"))}}
    if not _audit(ident, "delete_record", {**det, "phase": "intent"}, True, critical=True):
        return _err("refusing to mutate: the audit log is unwritable (accounting is a control).")
    ok, data = _cf("DELETE", f"/zones/{zid}/dns_records/{record_id.strip()}")
    _audit(ident, "delete_record", {**det, "phase": "result"}, ok, critical=True)
    if not ok:
        return _err(_cf_errors(data))
    return _out({"deleted": (data.get("result") or {}).get("id") or record_id.strip(), "zone": zname})


# Drop resource/prompt handlers we don't implement (keeps clients from probing them).
from mcp import types as _t
for _rt in (_t.ListResourcesRequest, _t.ReadResourceRequest, _t.ListResourceTemplatesRequest,
            _t.ListPromptsRequest, _t.GetPromptRequest, _t.SubscribeRequest, _t.UnsubscribeRequest):
    mcp._mcp_server.request_handlers.pop(_rt, None)

if __name__ == "__main__":
    # Config was already validated at import (_validate_config) — fail-closed on any path.
    mcp.run(transport="streamable-http")
