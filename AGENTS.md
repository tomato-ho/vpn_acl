# AGENTS.md

VPN Access Control: OpenVPN access control with per-user nftables policy, a C++17/CMake
daemon set, MariaDB, and a Vue 3 admin UI. RADIUS accounting is an **optional**
output; the default path has no FreeRADIUS/PAM dependency.

## Build and test

- `./configure.sh` is the canonical build: configures with DB and ADMIN on, builds,
  runs `ctest`, then installs the binaries to `/usr/local/sbin`.
- Manual equivalent:
  `cmake -S . -B build -DVPN_WITH_DB=ON -DVPN_WITH_ADMIN=ON && cmake --build build -j && ctest --test-dir build --output-on-failure`
- Run one test: `ctest --test-dir build -R vpncore_tests --output-on-failure`, or run
  the binary directly, e.g. `./build/vpncore_tests`.
- Tests are self-contained: no database, network, nftables, or fixtures required.
- Delivery checks: `deploy/verify.sh` (running stack, 30+ checks),
  `deploy/test-restore.sh` (backup → temp MariaDB → compare), `deploy/upgrade.sh
  --check|--rollback`, and `deploy/check-version.sh` (CMake / package.json / README /
  CHANGELOG must agree; CI enforces this). `deploy/upgrade.sh` runs `ctest` before
  rebuilding images.
- Version comes from `project(VERSION ...)` → generated `vpn/version.h`; binaries
  accept `--version` and `/readyz` reports `version`.
- Prerequisites: C++17 compiler, OpenSSL, MariaDB Connector/C (`pkg-config mariadb`
  or `libmariadb`), and spdlog. `VPN_WITH_DB` and `VPN_WITH_SPDLOG` default ON;
  `VPN_WITH_ADMIN` defaults OFF, so plain CMake will not build `vpn-admin`.
  RADIUS accounting uses an in-tree client (`libvpncore/src/radius.cpp`); libradcli
  is **not** a dependency.
- Frontend: `cd vpn-admin/web && npm ci && npm run build` (runs `vue-tsc`, then Vite;
  output is `vpn-admin/web/dist`). `npm run dev` proxies `/api` and `/metrics` to
  `127.0.0.1:8080`.

## Layout

- `libvpncore/` — config parsing, DB wrapper, CIDR/policy computation, nftables script
  generation, password hashing, IPC, and the optional RADIUS accounting client
  (`radius.cpp`: RFC 2866 encoding, MD5 authenticator, UDP retransmission).
- `libvpnservice/` — DB-backed domain logic shared by `vpn-admin` and tests. Put new
  user/group/service write logic here, not in HTTP handlers.
  `src/history_source.h` merges `vpn_sessions` + `vpn_session_history` for read paths;
  `src/access_log.cpp` queries `vpn_access_log` for the audit views.
- `vpn-policyd/` — long-running daemon. Owns nftables table `vpn_acl`, applies per-user
  chains, archives finished sessions, optionally sends RADIUS accounting, reconciles
  sessions, and kicks clients through the OpenVPN management socket.
- `vpn-client-connect/`, `vpn-client-disconnect/` — OpenVPN hooks. Connect loads policy,
  calls `vpn-policyd` over a Unix socket, and writes the per-client config; it requires a
  fixed tunnel IP.
- `vpn-auth-check/` — OpenVPN `auth-user-pass-verify` entry point. Reads the credential
  file, checks `vpn_users.password_hash`, enforces failure rate limits, writes
  `vpn_auth_log`, and returns an auth-failed reason via `auth_failed_reason_file`.
- `vpn-policyctl/` — CLI for groups, users, services, passwords, admins, and retention.
- `vpn-admin/` — C++ HTTP API (`/api/*`, `/metrics`) using cpp-httplib and nlohmann/json
  from `third_party/`. It does **not** serve the SPA; nginx serves `web/dist`.
- `sql/` — schema and migrations. `deploy/` — compose, containerfiles, nginx config,
  install/save-images/stage-app scripts, tmpfiles, Prometheus alerts.
  `freeradius/` — optional RADIUS container (compose profile).

## Architecture facts

- Effective policy: `push_routes = allow - deny`. Forward rules permit `push_routes`;
  input rules permit only enabled `vpn_server_services`. Every user needs a fixed IP
  inside their group range and, when configured, inside `tunnel_network`.
- Any DB change that affects policy must call `bump_policy_version()`. `vpn-policyd`
  skips a full REFRESH when `vpn_policy_version.version` is unchanged. `vpn-admin` also
  sends REFRESH after mutations, but that does not replace the version bump.
- `vpn-policyd` requires a fresh OpenVPN status file (`status_file`, grace period
  `reconcile_grace`); a stale or invalid snapshot causes refresh/reconcile to be skipped.
  The default path is `/run/openvpn-server/status.log`.
- nftables is managed by shelling out to `nft_bin`, not by linking libnftables.
- IPC is a Unix stream: command line, then `key=value` lines, then `END`. The peer UID
  must equal the configured `allowed_uid`. Default socket:
  `/run/vpn-policyd/policyd.sock`.
- Passwords: admin accounts (`vpn_admins`) and VPN users (`vpn_users.password_hash`)
  both use `pbkdf2-sha256$<iterations>$<salt>$<hash>`. VPN users are verified by
  `verify_user_password()`, which also accepts the legacy
  `{PBKDF2-SHA256}...` radcheck form.
- Sessions: `vpn_sessions` holds online sessions only. On disconnect,
  `vpn-policyd` archives into `vpn_session_history` (keyed by `acct_session_id`,
  idempotent) before deleting the online row. The connect hook writes
  `/run/vpn-policyd/clients/<user>@<ip>@<time_unix>` so the disconnect hook can
  match its own `session_id` even after a reconnect.
- Recovery: if a status client has no session row, `reconcile` reuses the exact
  connect marker when present; otherwise `recovery_identity()` derives an ID from
  `connected_since`, so different connections cannot overwrite one history row.
  Recovery is skipped when the status `connected_since` predates that
  user/IP's latest archived `stop_time` (`recovery_is_stale`), which prevents a
  post-restart stale status from creating a duplicate recovered session.
- Policy/session mutations (`connect`, `disconnect`, `refresh`, `reconcile`) are
  serialized by a process-wide mutex in `vpn-policyd`; reconcile runs on a timer
  thread, so this mutex is what prevents orphan cleanup from racing a new connect.
- Auth audit: `vpn_auth_log` (username, remote_ip, success, reason). Rate limiting is
  5 failures/5 min per username+IP and 20/5 min per IP; unknown users perform a
  dummy PBKDF2 and client-visible errors are generic.
- Access audit: nft sets `flows` / `flows_rev` / `flows_deny` (key `ip saddr . ip daddr`,
  per-element `counter`; allow/rev timeout 24h, deny 10m). Forward/input chains put
  `iifname tun0 ... vmap @user_fwd|user_in` **before** the generic
  `ct state established,related accept`, so established traffic is counted and a
  revoked policy immediately drops client→target packets (reverse traffic still hits
  the counter/accept rule first; it is counted but not policy-filtered).
  `vpn-policyd` samples them every
  `flow_sample_interval` seconds into `vpn_access_log` (one row per
  session × dest × allow/deny) inside one DB transaction and stores the raw counters
  in `vpn_flow_state` so a restart continues from the previous baseline.
  Cleanup order is: final sample → remove nft rules → archive session → flush set
  elements/state; archive failure keeps counters for retry.
  `vpn-policyd` rebuilds the whole `vpn_acl` table in one atomic script when the sets
  are missing or were created by an older timeout; rebuild resets `vpn_flow_state`.
  Startup verifies `vpn_access_log`, `vpn_flow_state` and
  `vpn_session_history.session_id` and exits if migrations are missing.
- Fixed tunnel IPs must not be the tunnel network/broadcast address or the
  OpenVPN gateway (first host), and must not equal `allowed_service_ips`;
  `validate_fixed_ip`, group range validation, settings updates and
  `compute_effective_policy` all enforce this. `max_rules_per_user` /
  `max_services_per_user` are enforced on writes/enables, not only at connect.
- Security hardening: DB root and app passwords must be distinct (install generates
  separate values; existing `.env` must be rotated manually). Nginx sets CSP and
  security headers for SPA assets; `vpn-admin` `/metrics` accepts only loopback /
  the Podman gateway; policyd chmods the OpenVPN management socket to 0660.
  Audit sampling logs a warning at 90% of the 65536 set capacity or 10000 active
  targets for one session.
- Admin API auth is a session cookie plus `X-CSRF-Token` on non-GET requests; use the
  existing `require_session(..., true)` path for new mutating routes.

## Config and deployment gotchas

- Config files are `key=value`. `VPN_DB_HOST`, `VPN_DB_PORT`, `VPN_DB_NAME`,
  `VPN_DB_USER`, and `VPN_DB_PASSWORD` override the corresponding `db_*` file keys.
  `VPN_RADIUS_SECRET` overrides `radius_secret`. `VPN_ADMIN_BIND` overrides `bind`
  (needed inside containers: bind `0.0.0.0`, publish on `127.0.0.1`).
- All containers inherit `TZ` from `.env` (`TZ: ${TZ:-Asia/Shanghai}` in
  `compose.yaml`). Keep it set for `policyd`, `openvpn`, `web` and `retention` too;
  otherwise their spdlog/OpenVPN/nginx timestamps are UTC while DB and `vpn-admin`
  are local. Recreate containers (not just restart) after changing `TZ`.
- Accounting is optional: `accounting_enabled=1` plus `radius_server` / `radius_port` /
  `radius_secret` (`radius_timeout_ms`, `radius_retries`). Start FreeRADIUS with
  `podman-compose --profile radius up -d`. There is no radcli config file.
- Access audit sampling: `flow_sample_interval` (default 30s, clamped 5..300) must stay
  below the allow/rev set timeout (24h) and deny timeout (10m).
  `retention-cleanup --access-days N` controls `vpn_access_log` / `vpn_flow_state`
  retention (default 180 days). The policyd startup schema check requires the
  migrations, so deploy `deploy/migrate.sh` before replacing binaries.
- A config path that is a directory resolves to `<dir>/vpn-policy.conf`. Defaults:
  `vpn-policyctl`/`vpn-client-connect`/`vpn-auth-check` use `/etc/vpn-policy/config`,
  `vpn-policyd` uses `policyd.conf`, and `vpn-admin` uses `admin.conf`.
- `deploy/install.sh` generates `.env`, configs, Web certs, OpenVPN CA/server cert/ta.key,
  applies SQL, builds the image, and starts the stack. It is idempotent: existing files
  are left untouched. `--with-deps` installs the EL10 build/runtime packages first
  (`podman`, `podman-compose`, `gcc-c++`, `make`, `cmake`, `pkgconf-pkg-config`,
  `openssl-devel`, `mariadb-connector-c-devel`, `spdlog-devel` via EPEL, `nodejs`,
  `nodejs-npm`, `nftables`, `openvpn`, `curl`, `iproute`, `tar`, `gzip`); `--check` only
  reports what is missing. `deploy/stage-app.sh` resolves the OpenVPN binary from
  `VPN_OPENVPN_BIN`, then `PATH`, then `/data/app/openvpn-2.7.9/sbin/openvpn`.
- Air-gapped installs: `deploy/save-images.sh` exports mariadb/nginx/app images to
  `deploy/images/*.tar`; `install.sh --offline` loads them and refuses to continue if any
  required image is still missing. `--proxy URL` exports `http(s)_proxy`/`no_proxy` for
  dnf/npm/podman. The host clock must be NTP-accurate; skew makes clients reject the
  freshly signed CA (`certificate is not yet valid`).
- Reliability regression: `deploy/test-reliability.sh` (needs a running stack)
  covers reconnect isolation, concurrent connects, policy-version polling,
  reconcile recovery and stale-status recovery (no duplicate recovered history).
  `deploy/test-access-audit.sh` covers allow/deny flow
  accounting (ICMP + TCP upload/download), mid-transfer policy revocation,
  policyd restart continuity and final sampling;
  `deploy/test-guards.sh` covers fixed-IP/group-range reservation, write-time
  rule/service limits and per-IP/username auth throttling.
  `test-access-audit.sh` temporarily adds `tun0`/the peer veth to the firewalld
  `trusted` zone and restores it on exit. `deploy/soak-faults.sh` injects faults on
  a schedule and `deploy/soak-monitor.sh` samples health/resources to CSV for long runs.
- `install.sh` does not touch firewalld: open `http`, `https`, `1194/udp` manually and
  add masquerade for the tunnel network on routed deployments.
- Compose runs six services: `mariadb`, `policyd`, `openvpn`, `admin` (`app`), `web`,
  `retention` (daily `retention-cleanup --apply` loop).
  `policyd` and `openvpn` use `network_mode: host` because they create `tun0` and manage
  host nftables; both need `NET_ADMIN`, and `openvpn` needs `/dev/net/tun`.
- `/run/vpn-policyd` and `/run/openvpn-server` are shared between containers. They are
  declared in `deploy/vpn-policy.tmpfiles` → `/etc/tmpfiles.d/`, because a bind mount to
  a deleted/recreated directory leaves the container looking at an empty inode.
- `deploy/app.Containerfile` does not compile or fetch packages: `deploy/stage-app.sh`
  collects the locally built binaries, the host `nft`, and the non-base shared libraries
  (`libmariadb`, `libspdlog`, `libfmt`, `libnl*`, `liblzo2`, `liblz4`, `libcap-ng`,
  nftables libs) into `deploy/build-context/` (gitignored). The base image is pinned to
  Rocky Linux 10, so binaries must be built on an EL10 host.
- `sql/` is not auto-applied by Compose; `install.sh` calls `deploy/migrate.sh`, which
  applies every `sql/*.sql` in filename order and records it in `schema_migrations`
  (skipping 006/008 when the optional FreeRADIUS tables are absent). FreeRADIUS tables
  (`radcheck`, `radacct`, `radpostauth`, `nas`, …) are optional and must be imported
  separately.
- Re-running `sql/001_vpn_schema.sql` resets `vpn_settings` to its default values.
- Do not hand-edit `vpn-admin/web/dist`; rebuild from `web/src`.
- `tunnel_network` has two sources of truth: `vpn_settings.tunnel_network` and the
  `server` directive in `deploy/openvpn/server.conf`. Keep them in sync. Changing it also
  requires updating group ranges, user fixed IPs, gateway-scoped services, the firewall
  masquerade and `vpn_policy_version`; see README「修改隧道网段」and
  `deploy/examples/change-tunnel-network.sql`.