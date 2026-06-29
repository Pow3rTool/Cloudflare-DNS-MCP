"""Unit tests for the security fences — no network, no real Entra. Run: python test_server.py

Sets a valid-looking config in the env BEFORE importing server (import triggers the
fail-closed _validate_config), then exercises the pure-logic gates: _authz, _writable,
_readable, _redact, _rate_ok, _identity (fail-closed cases), _resolve_zone (stubbed _cf).
These are the bits that silently break on a refactor — keep them honest.
"""
import os, sys, tempfile

os.environ.update({
    "CFDNS_API_TOKEN": "cfut_unit_test",
    "CFDNS_TENANT_ID": "00000000-0000-0000-0000-000000000001",
    "CFDNS_CLIENT_ID": "00000000-0000-0000-0000-000000000002",
    "CFDNS_REQUIRED_SCOPE": "user_impersonation",
    "CFDNS_ALLOWED_CLIENTS": "00000000-0000-0000-0000-000000000003",
    "CFDNS_EDIT_ZONES": "example.com",
    "CFDNS_READ_ZONES": "",
    "CFDNS_ALLOW_ACCOUNT_READ": "false",
    "CFDNS_WRITE_RATE_PER_MIN": "3",
    "CFDNS_AUDIT_LOG": os.path.join(tempfile.mkdtemp(), "audit.log"),
})
import server as s  # noqa: E402

_P, _F = [], []
def check(name, cond):
    (_P if cond else _F).append(name)
    print(("ok   " if cond else "FAIL ") + name)

# --- _authz: reads need Dns.Read|Dns.Write, writes need Dns.Write -----------
check("authz_read_with_read",      s._authz(["dns.read"],  write=False)[0] is True)
check("authz_read_denied_no_role", s._authz([],            write=False)[0] is False)
check("authz_write_needs_write",   s._authz(["dns.read"],  write=True)[0]  is False)
check("authz_write_ok",            s._authz(["dns.write"], write=True)[0]  is True)
check("authz_write_allows_read",   s._authz(["dns.write"], write=False)[0] is True)

# --- _writable / _readable (fence defaults to EDIT_ZONES) ------------------
check("writable_in_list",     s._writable("zid", "example.com")[0] is True)
check("writable_out_of_list", s._writable("zid", "other.com")[0]  is False)
check("readable_in_fence",    s._readable("zid", "example.com")[0] is True)
check("readable_out_of_fence",s._readable("zid", "other.com")[0]  is False)

# --- _redact: hash secret TXT/SPF, pass readable types ---------------------
check("redact_txt_hashed", s._redact("TXT", "v=spf1 secret").startswith("sha256:"))
check("redact_a_plain",    s._redact("A", "1.2.3.4") == "1.2.3.4")

# --- _rate_ok: per-operator sliding budget (cap 3) -------------------------
check("rate_under_cap", all(s._rate_ok("u1") for _ in range(3)))
check("rate_over_cap",  s._rate_ok("u1") is False)
check("rate_other_oid_independent", s._rate_ok("u2") is True)

# --- _identity: fail-closed cases (no network) -----------------------------
check("identity_no_bearer", s._identity("") is None)
check("identity_bad_token", s._identity("not.a.jwt") is None)
_save = s.TENANT; s.TENANT = ""
check("identity_unconfigured_failclosed", s._identity("a.b.c") is None)
s.TENANT = _save

# --- _resolve_zone: stubbed CF (name + id), and fail-closed unresolved id --
_orig = s._cf
s._cf = lambda m, p, **k: ((True, {"result": [{"id": "zone123", "name": "example.com"}]})
                           if p == "/zones"
                           else (True, {"result": {"id": "abcdef0123456789abcdef0123456789", "name": "byid.example"}}))
check("resolve_by_name", s._resolve_zone("example.com")[1] == "example.com")
check("resolve_by_id",   s._resolve_zone("abcdef0123456789abcdef0123456789")[1] == "byid.example")
s._cf = lambda m, p, **k: (False, {"errors": [{"message": "nope"}]})
check("resolve_unresolved_id_fails_closed", s._resolve_zone("f" * 32)[2] is not None)
s._cf = _orig

print(f"\n{len(_P)} passed, {len(_F)} failed")
sys.exit(1 if _F else 0)
