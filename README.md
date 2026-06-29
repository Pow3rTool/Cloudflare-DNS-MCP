# cloudflare-dns-mcp — scoped Cloudflare DNS, as an MCP server

A deliberately small MCP tool surface for reading and managing Cloudflare DNS:
**`search_zones`**, **`search_records`**, **`create_record`**, **`edit_record`**,
**`delete_record`**. All writes (create/edit/delete) are gated to a per-server zone
allow-list; `delete_record` takes a record id (never a name) so it can't be done by guess.

It is the cousin of [`azobo`](../Azure-CLI-MCP/) — same fleet conventions (Python +
FastMCP, bearer-validating front door, systemd sandbox, nginx TLS) — but **structurally
simpler**, because Cloudflare's API has no OBO.

## Why there's no "identity all the way through" (and that's fine)

azobo propagates the signed-in user to Azure via OAuth On-Behalf-Of: every downstream
call is *the user*, bounded by *their* Azure RBAC. **Cloudflare cannot do this.** The CF
API only trusts Cloudflare-issued credentials (API tokens); it has no federated-token
trust anchor, so your Entra identity can authenticate you to the *dashboard* (via SSO)
but can never become a token the CF API accepts. (We confirmed this the hard way —
SSO/Access yields a browser session, not an API credential; replaying that is a brittle
anti-pattern.) So this server splits the difference:

- **Front door — who you are.** Validate the operator's Entra bearer (signature via JWKS,
  audience, issuer, expiry), exactly like azobo, **minus the broker** (there's nothing to
  mint). Attribution lives in *our* audit log, keyed to the human.
- **Back end — what gets done.** One **account-scoped Cloudflare API token**
  (`Zone:Read` + `DNS:Edit`), the same for every operator. Never per-user.

## The two-layer boundary

| Layer | Enforced by | What it bounds |
|-------|-------------|----------------|
| **Ceiling** | the CF token's scope | The lab account's zones, DNS only. **Cannot reach prod** (separate account). |
| **Floor** | this server (`CFDNS_EDIT_ZONES`) | create/edit/**delete** only touch allow-listed zones; deletes require an explicit record id. |

**Reads** are fenced too: `CFDNS_READ_ZONES` if set, else they default to `CFDNS_EDIT_ZONES`,
and only span the whole account when `CFDNS_ALLOW_ACCOUNT_READ=true` is set explicitly.
**Writes** are always fenced to `CFDNS_EDIT_ZONES`. Widen either zone-by-zone without
re-minting the token.

## Tools

| Tool | Verb | Notes |
|------|------|-------|
| `search_zones(query="", limit=50)` | read | substring match on zone name; paginates (prod 350+ zones). Needs `Zone:Read`. |
| `search_records(zone, query="", type="", limit=100)` | read | `zone` = name or 32-hex id; `query` matches record name OR content. |
| `create_record(zone, type, name, content, ttl=1, proxied=False, comment="")` | write | gated by `CFDNS_EDIT_ZONES`. `proxied` defaults **false** (dumb DNS / grey-cloud). |
| `edit_record(zone, record_id, …fields)` | write | PATCH; only the fields you pass change. gated by `CFDNS_EDIT_ZONES`. |
| `delete_record(zone, record_id)` | write | DELETE by id (never by name). gated by `CFDNS_EDIT_ZONES`. Destructive, no undo. |

The model `search_zones` → `search_records` → grab the `record_id`/`zone` → `edit_record`/`delete_record`.

## Token (Cloudflare side)

Create a **scoped API token** (My Profile → API Tokens) with **DNS:Edit**, Zone Resources
= the lab account. Verify:

```bash
curl -s https://api.cloudflare.com/client/v4/user/tokens/verify \
  -H "Authorization: Bearer $CFDNS_API_TOKEN"
```

> Empirically a `DNS:Edit` (all-zones) token already lists zones and resolves names
> (CF returns zones you hold any permission on), so all five tools work with DNS:Edit
> alone. Adding **Zone:Read** is harmless and makes intent explicit, but isn't required.

## Deploy (co-located on the MCP host, next to peer-mcp)

`dns-mcp.example.com` resolves to `the MCP host` (the peer-mcp box) and rides the **same combined
cert** as peer-mcp — cert **NNN** (PHP7-CertBot, auto-renewed, same key), now extended with
the `cfmcp` SAN. The vhost follows the `/ai/<app>/nginx.conf` house style: one combined
`*.pem` (cert+chain+key) referenced by *both* `ssl_certificate` directives, plus the shared
`include /opt/nginx/include/listenssl.conf;`. New lab MCPs on this box = just another SAN
on NNN — no per-vhost cert to manage.

The `the MCP host` box is self-contained under `/opt/<app>/` (not the `/etc` + `/var/lib` split):

```bash
# runtime + code
python3 -m venv /opt/cloudflare-dns-mcp/venv
/opt/cloudflare-dns-mcp/venv/bin/pip install -r requirements.txt
install -m 755 server.py /opt/cloudflare-dns-mcp/

# user + per-app etc/ (conf + pem) and var/ (audit)
useradd --system --no-create-home --shell /usr/sbin/nologin cfdns
install -d /opt/cloudflare-dns-mcp/etc
install -d -o cfdns -g cfdns -m 700 /opt/cloudflare-dns-mcp/var

# config (the CF token is secret -> 0640, cfdns-readable)
cp .env.example /opt/cloudflare-dns-mcp/etc/cloudflare-dns-mcp.env   # fill in CFDNS_API_TOKEN
chown root:cfdns /opt/cloudflare-dns-mcp/etc/cloudflare-dns-mcp.env
chmod 640 /opt/cloudflare-dns-mcp/etc/cloudflare-dns-mcp.env

# service
cp deploy/cloudflare-dns-mcp.service /etc/systemd/system/
systemctl enable --now cloudflare-dns-mcp

# vhost — wired the way peer-mcp's is on the MCP host (whatever include dir that box uses)
cp deploy/nginx-cloudflare-dns.conf /opt/.../  # match peer-mcp's vhost location
nginx -t && systemctl reload nginx
```

Verify: `systemctl is-active cloudflare-dns-mcp`, then an MCP `initialize` to
`https://dns-mcp.example.com/` lists the five tools.

### Cert (shared NNN, PHP7-CertBot)

`dns-mcp.example.com` is a SAN on combined cert **NNN** (same key as peer-mcp). The renew
job — usually just a cron'd `curl` of the keyhash endpoint — needs to **install the fetched
combined pem into both app folders** and reload nginx, e.g.:

```bash
# fetch once, write to every app that shares cert NNN, then reload
curl -s "<certbot-keyhash-endpoint-for-cert-NNN>" -o /tmp/NNN.pem    # the existing line
install -m 0640 /tmp/NNN.pem /opt/peer-mcp/etc/peer-mcp.pem                 # existing target
install -m 0640 /tmp/NNN.pem /opt/cloudflare-dns-mcp/etc/cloudflare-dns-mcp.pem  # NEW target
shred -u /tmp/NNN.pem
nginx -s reload
```

(Or, to skip the dual-write entirely: point cfmcp's `ssl_certificate` at peer-mcp's existing
`/opt/peer-mcp/etc/peer-mcp.pem` — nginx runs as root and reads it fine. Kept separate above only
to honor the self-contained `/opt/<app>/` convention.)

## Lab vs prod

Same auth model everywhere — tokens are always validated (the fabric always carries a
turnstone OBO token in both). The only differences are which account the scoped CF token
targets and how wide you fence:

- **Lab (the lab account):** fill `CFDNS_TENANT_ID`/`CFDNS_CLIENT_ID`/`CFDNS_REQUIRED_SCOPE`/
  `CFDNS_ALLOWED_CLIENTS` (the lab tenant + turnstone app). `CFDNS_EDIT_ZONES` = the lab
  zones you'll edit; `CFDNS_ALLOW_ACCOUNT_READ=true` if you want search across the whole
  lab account.
- **Prod:** same knobs against the prod tenant/app; a **prod-account** scoped CF token;
  per-tenant `CFDNS_EDIT_ZONES`; leave account-read off and fence reads deliberately.

## Entra app registration (the front door)

Built by turnstone (verify in the portal). Because this server is a **pure resource API**
— it only *validates* the incoming bearer and never authenticates *outbound* to Entra (no
OBO, no Graph) — it needs **no client secret, no certificate, no redirect URI, and no Graph
API permissions**. Just these, fed to the env:

| Thing | Value | Used as |
|-------|-------|---------|
| `cloudflare-dns-mcp` app (resource) | `<resource-app-client-id>` | `CFDNS_CLIENT_ID` (v2 tokens → this GUID is the `aud`) |
| Identifier URIs | `https://dns-mcp.example.com` + `api://<resource-app-client-id>` | the `https://` form MUST exist — turnstone sends it as the RFC 8707 `resource` (= the server URL); without it you get `invalid_target`/AADSTS9010010 |
| `user_impersonation` scope | `<user-impersonation-scope-id>` | turnstone requests `https://dns-mcp.example.com/user_impersonation`; `CFDNS_REQUIRED_SCOPE=user_impersonation` |
| Service principal | `<resource-sp-object-id>` | makes the app consentable/assignable |
| turnstone-MCP grant + admin consent | `user_impersonation` (AllPrincipals) | turnstone can mint OBO tokens for this API |
| turnstone-MCP client app id | `<turnstone-client-appid>` | `CFDNS_ALLOWED_CLIENTS` (restrict callers) |

**turnstone client-side:** its `mcp_servers` entry for cfmcp requests scope
`https://dns-mcp.example.com/user_impersonation` (+ `offline_access`), audience
`<resource-app-client-id>`. turnstone also emits the RFC 8707 `resource` = the server URL, which is
why the matching `https://` identifier URI above is required.

The three "missing" items from the setup (client secret/cert, redirect URIs, Graph
permissions) are **intentionally not needed here** — they'd only matter if cfmcp did an OBO
exchange or called other APIs. It doesn't; the only outbound credential it holds is the
static Cloudflare token.

## Security notes

- TLS is load-bearing — the operator bearer rides every request (nginx terminates it).
- The CF token is the crown jewel here; it's in a `0640` env file readable only by `cfdns`,
  and the unit blocks link-local/metadata egress.
- Writes (create/edit/delete) are confined to `CFDNS_EDIT_ZONES`; `delete_record` additionally
  requires an explicit record id (no name-based deletes), so a confused agent can't wipe a record
  it merely guessed the name of. Deletes are destructive with no undo — scope the allow-list
  accordingly (e.g. don't add a zone you're not prepared to have records removed from).
- **Delete authZ is the `Dns.Write` role by design** — write *includes* delete; there is no
  separate `Dns.Delete` role. Delete is additionally off unless `CFDNS_ENABLE_DELETE=true`
  (a global kill-switch), so the two gates are: writer + delete-enabled. This is intentional,
  not an oversight — if you want delete to be a distinct grant, split the role; otherwise a
  `Dns.Write` holder on an allow-listed zone can delete when the switch is on.
- `proxied=false` default keeps records grey-cloud (CF as dumb DNS), matching the fabric's
  stance that Cloudflare is resolution only, never in the data/identity path.

## AAA

- **Authentication** — **always on, no unauth path.** Every request's Entra bearer is
  cryptographically verified (JWKS signature, audience, issuer, expiry) + the coarse scope
  and the calling client (turnstone) are pinned. Startup refuses to boot without
  tenant/client/scope/allowed-client set. No bearer → rejected.
- **Authorization** — **enforced via Entra app roles** in the token's `roles` claim
  (confirmed to survive turnstone's OBO): **`Dns.Read`** for reads, **`Dns.Write`** for
  writes; a validated token with no matching role is denied. Assign users/groups to those
  roles on the resource app in Entra. (Entra's "user assignment required" *toggle* is a
  no-op behind OBO — the `roles` claim, not the toggle, is what carries through.) The token's
  `tid` is pinned to the configured tenant GUID (multi-tenant aliases refused). Reads are
  additionally fenced to `CFDNS_READ_ZONES` → else `CFDNS_EDIT_ZONES` → else account-wide
  only with `CFDNS_ALLOW_ACCOUNT_READ=true`; writes are fenced to `CFDNS_EDIT_ZONES`.
  Writers are rate-limited per operator (`CFDNS_WRITE_RATE_PER_MIN`, sliding 60s window).
- **Accounting** — append-only JSONL audit (`CFDNS_AUDIT_LOG`, `0600`); writability is
  checked at startup, and a dropped line always hits stderr/journald (audit is a control).
  Each record carries the immutable `oid` + `who` (upn) + verb + target + `ok`. Mutations
  write **two** lines — an `intent` line *before* the Cloudflare call (and the mutation is
  **refused** if that write fails) and a `result` line after — and are **reconstructable**:
  edits log the `before` snapshot + `changes`, deletes log the `deleted_record`. Secret-bearing
  `TXT`/`SPF` content is hashed (`sha256:…`), never logged raw. Denials log `ok:false` + reason.

## Tests

`python test_server.py` — no network, no Entra. Covers the security fences (`_authz`,
`_writable`/`_readable`, `_redact`, `_rate_ok`, `_identity` fail-closed cases, `_resolve_zone`
with a stubbed CF). These are the bits a refactor silently breaks; run them before shipping.

## License

**GNU Affero General Public License v3.0** (`AGPL-3.0-or-later`) — see [LICENSE](LICENSE).
AGPL (not plain GPL) because this is a network service: §13 closes the SaaS loophole so a
modified hosted version must still offer its source. SPDX-License-Identifier: AGPL-3.0-or-later
