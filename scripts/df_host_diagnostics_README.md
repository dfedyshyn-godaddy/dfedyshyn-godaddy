# DF webslave host diagnostics

Local health-check for a Domain Factory webslave host (the containerized
shared-hosting stack: `dockerd -> nginx -> apache -> phpNN`). Read-only,
no destructive actions — safe to run on a live host.

Two files, same script, two delivery methods:

- **`df_host_diagnostics.sh`** — run as a normal file (`scp` it over, or
  create it on the host, `chmod +x`, execute).
- **`df_host_diagnostics_pastable.sh`** — the same script wrapped in a
  `bash -s -- <<'DFDIAG' ... DFDIAG` heredoc, safe to copy-paste directly
  into an interactive SSH session (see "Why the pastable variant" below).

## What it checks

- **Host identity** — hostname, derived SID (`mcNNNNN` → `webNNNNN`,
  DF's own hostname convention), kernel, uptime.
- **System resources** — load average vs. core count, memory headroom,
  disk usage per filesystem (flags anything ≥80%/90%).
- **Docker daemon** — is `dockerd` up and reachable.
- **Core containers** — `nginx`/`apache` container status and restart
  counts; `docker exec nginx nginx -t` (config test must run *inside*
  the container — the host's `nginx` binary isn't the live config).
- **PHP-FPM pools** — status of `phpNN_<domain>` alt-php containers;
  FCGI socket lookup under `/run/php` for a given domain.
- **Apache error log** (`/var/log/df/apache/error.log`) — tail + error
  density check, optionally filtered to one domain.
- **OOM / kernel errors** — `journalctl -k` / `dmesg` for OOM-kill
  events in the last 24h.
- **Docker disk usage** — `docker system df`.
- **Malware / webshell diagnostics** — same approach as
  [`web_malware_scan.sh`](README.md): generic discovery of whatever
  AV/rootkit tooling is actually installed (no guessing binary names
  one by one), plus dependency-free signature checks: obfuscated
  `eval(base64_decode/gzinflate/str_rot13)`, direct
  `system/exec/passthru/shell_exec/proc_open/assert($_GET/POST/REQUEST/COOKIE)`
  webshell patterns, recently-modified PHP files, PHP files under
  `uploads/`, world-writable PHP files, download-and-execute cron
  entries, and suspicious running processes.

## Usage

```bash
./df_host_diagnostics.sh                                    # auto-detect everything
./df_host_diagnostics.sh example.com                         # narrow to one vhost
./df_host_diagnostics.sh example.com /var/www/vhosts/example.com   # explicit webroot
SCAN_DAYS=14 ./df_host_diagnostics.sh example.com            # widen "recently changed" window (default 7)
```

### Pastable variant

For sessions where you can't easily `scp` a file over (e.g. a jump-host
session), copy the entire contents of `df_host_diagnostics_pastable.sh`
and paste it into the SSH session. Edit the first line's `''  ''` to
pass domain/webroot before pasting if you want them:

```bash
bash -s -- example.com /var/www/vhosts/example.com <<'DFDIAG'
... (script body) ...
DFDIAG
```

**Why not just paste `df_host_diagnostics.sh` directly?** Pasted
straight into an interactive shell (not run as a script), the script's
own `exit 0/1/2` at the end would close your SSH session, and `$1`/`$2`
would be unset since there's no way to pass positional args to a shell
you're already in. Wrapping it in `bash -s -- ARGS <<'DFDIAG'` runs it
as a separate subshell fed via heredoc: `exit` only ends that subshell,
`set -u`/`pipefail` don't leak into your login shell, and the args after
`-s --` become `$1`/`$2` inside the script.

## Output

Colorized `OK`/`WARN`/`CRIT` lines per check, a summary of all
warnings/criticals at the end, and a matching exit code.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All checks passed |
| `1`  | Only warnings found |
| `2`  | At least one critical issue found |
