#!/usr/bin/env bash
#
# df_host_diagnostics.sh — local diagnostics for a Domain Factory webslave host
# (containerized shared hosting stack: dockerd -> nginx -> apache -> phpNN)
#
# Run directly on the host (mcNNNNN / webNNNNN). Read-only, no destructive actions.
#
# Usage: ./df_host_diagnostics.sh [domain] [webroot]
#   domain  (optional) — narrow the apache/php-fpm/nginx/malware checks to one vhost
#   webroot (optional) — path to scan for webshell/malware signatures
#                         (e.g. /var/www/vhosts/<domain>); auto-detected if omitted
# Env: SCAN_DAYS=7   — how many days back to flag recently-modified PHP files

set -uo pipefail

DOMAIN="${1:-}"
WEBROOT="${2:-}"
LOG_LINES="${LOG_LINES:-40}"
SCAN_DAYS="${SCAN_DAYS:-7}"

C_RESET=$'\033[0m'
C_RED=$'\033[31m'
C_YEL=$'\033[33m'
C_GRN=$'\033[32m'
C_BLU=$'\033[34m'
C_BOLD=$'\033[1m'

WARN_COUNT=0
CRIT_COUNT=0
ISSUES=()

section() { printf '\n%s== %s ==%s\n' "$C_BOLD$C_BLU" "$1" "$C_RESET"; }
ok()      { printf '  [%sOK%s]   %s\n' "$C_GRN" "$C_RESET" "$1"; }
warn()    { printf '  [%sWARN%s] %s\n' "$C_YEL" "$C_RESET" "$1"; WARN_COUNT=$((WARN_COUNT+1)); ISSUES+=("WARN: $1"); }
crit()    { printf '  [%sCRIT%s] %s\n' "$C_RED" "$C_RESET" "$1"; CRIT_COUNT=$((CRIT_COUNT+1)); ISSUES+=("CRIT: $1"); }
info()    { printf '  %s\n' "$1"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
section "Host identity"
HOSTNAME_RAW="$(cat /etc/hostname 2>/dev/null || hostname)"
# mcNNNNN -> webNNNNN (strip 2-char prefix, per DF SID convention)
SID="web${HOSTNAME_RAW#??}"
info "hostname:      $HOSTNAME_RAW"
info "derived SID:   $SID"
info "kernel:        $(uname -r)"
info "uptime:        $(uptime -p 2>/dev/null || uptime)"
[ -n "$DOMAIN" ] && info "target domain: $DOMAIN"

# ---------------------------------------------------------------------------
section "System resources"

read -r LOAD1 LOAD5 LOAD15 <<<"$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
NPROC="$(nproc 2>/dev/null || echo 1)"
info "load avg (1/5/15m): ${LOAD1:-?} ${LOAD5:-?} ${LOAD15:-?}  (cores: $NPROC)"
if [ -n "${LOAD1:-}" ] && awk "BEGIN{exit !($LOAD1 > $NPROC*1.5)}"; then
  crit "load average ($LOAD1) exceeds 1.5x core count ($NPROC)"
else
  ok "load average within range"
fi

if have free; then
  MEM_LINE="$(free -m | awk '/^Mem:/{print $2, $3, $7}')"
  read -r MEM_TOTAL MEM_USED MEM_AVAIL <<<"$MEM_LINE"
  info "memory: ${MEM_USED}MB used / ${MEM_TOTAL}MB total (available ${MEM_AVAIL}MB)"
  if [ -n "${MEM_AVAIL:-}" ] && [ "$MEM_AVAIL" -lt $((MEM_TOTAL/10)) ]; then
    crit "available memory below 10% of total (${MEM_AVAIL}MB)"
  elif [ -n "${MEM_AVAIL:-}" ] && [ "$MEM_AVAIL" -lt $((MEM_TOTAL/5)) ]; then
    warn "available memory below 20% of total (${MEM_AVAIL}MB)"
  else
    ok "memory headroom looks fine"
  fi
fi

if have df; then
  info "disk usage (host filesystems >70% used):"
  df -hP 2>/dev/null | awk 'NR==1 || ($5+0)>=70 {print "    "$0}'
  FULLEST="$(df -hP 2>/dev/null | awk 'NR>1 {gsub("%","",$5); print $5, $6}' | sort -rn | head -1)"
  FULLEST_PCT="$(echo "$FULLEST" | awk '{print $1}')"
  FULLEST_MNT="$(echo "$FULLEST" | awk '{print $2}')"
  if [ -n "${FULLEST_PCT:-}" ]; then
    if [ "$FULLEST_PCT" -ge 90 ]; then
      crit "filesystem $FULLEST_MNT at ${FULLEST_PCT}% used"
    elif [ "$FULLEST_PCT" -ge 80 ]; then
      warn "filesystem $FULLEST_MNT at ${FULLEST_PCT}% used"
    else
      ok "no filesystem above 80% used"
    fi
  fi
fi

# ---------------------------------------------------------------------------
section "Docker daemon"

if ! have docker; then
  crit "docker binary not found in PATH"
else
  if have systemctl && systemctl is-active --quiet docker 2>/dev/null; then
    ok "dockerd is active (systemd)"
  elif docker info >/dev/null 2>&1; then
    ok "dockerd reachable"
  else
    crit "dockerd not reachable (docker info failed)"
  fi
fi

# ---------------------------------------------------------------------------
section "Core containers (nginx / apache)"

if have docker && docker info >/dev/null 2>&1; then
  for name in nginx apache; do
    CID="$(docker ps -qf "name=^${name}\$" 2>/dev/null)"
    if [ -z "$CID" ]; then
      # check if it exists but is stopped/restarting
      CID_ANY="$(docker ps -aqf "name=^${name}\$" 2>/dev/null)"
      if [ -n "$CID_ANY" ]; then
        STATUS="$(docker inspect -f '{{.State.Status}} (restarts: {{.RestartCount}})' "$CID_ANY" 2>/dev/null)"
        crit "container '$name' is not running: $STATUS"
      else
        crit "container '$name' does not exist"
      fi
      continue
    fi
    STATUS="$(docker inspect -f '{{.State.Status}} since {{.State.StartedAt}} (restarts: {{.RestartCount}})' "$CID" 2>/dev/null)"
    RESTARTS="$(docker inspect -f '{{.RestartCount}}' "$CID" 2>/dev/null)"
    if [ -n "$RESTARTS" ] && [ "$RESTARTS" -gt 5 ]; then
      warn "container '$name' has restarted $RESTARTS times"
    else
      ok "container '$name': $STATUS"
    fi
  done

  # nginx config test must run inside the container (host nginx binary != live config)
  if docker ps -qf 'name=^nginx$' >/dev/null 2>&1 && [ -n "$(docker ps -qf 'name=^nginx$')" ]; then
    if NGINX_T_OUT="$(docker exec nginx nginx -t 2>&1)"; then
      ok "nginx -t (in-container) syntax OK"
    else
      crit "nginx -t (in-container) failed:"
      echo "$NGINX_T_OUT" | sed 's/^/    /'
    fi
  fi
else
  warn "skipping container checks — docker not reachable"
fi

# ---------------------------------------------------------------------------
section "PHP-FPM pools (alt-php phpNN_<domain>)"

if have docker && docker info >/dev/null 2>&1; then
  PHP_CONTAINERS="$(docker ps -a --format '{{.Names}}\t{{.Status}}' 2>/dev/null | grep -E '^php[0-9]+' || true)"
  if [ -z "$PHP_CONTAINERS" ]; then
    warn "no phpNN_* containers found"
  else
    TOTAL=0; DOWN=0
    while IFS=$'\t' read -r NAME STATUS; do
      [ -z "$NAME" ] && continue
      TOTAL=$((TOTAL+1))
      if [ -n "$DOMAIN" ] && [[ "$NAME" != *"$DOMAIN"* ]]; then
        continue
      fi
      if [[ "$STATUS" == Up* ]]; then
        [ -n "$DOMAIN" ] && ok "pool '$NAME': $STATUS"
      else
        DOWN=$((DOWN+1))
        crit "pool '$NAME' not up: $STATUS"
      fi
    done <<<"$PHP_CONTAINERS"
    if [ "$DOWN" -eq 0 ]; then
      ok "all $TOTAL php-fpm pool containers are Up"
    else
      crit "$DOWN of $TOTAL php-fpm pool containers are down"
    fi
  fi

  if [ -n "$DOMAIN" ]; then
    SOCK_MATCH="$(find /run/php -maxdepth 2 -iname "*${DOMAIN}*" 2>/dev/null)"
    if [ -n "$SOCK_MATCH" ]; then
      ok "FCGI socket found for $DOMAIN:"
      echo "$SOCK_MATCH" | sed 's/^/    /'
    else
      warn "no FCGI socket under /run/php matching '$DOMAIN' (sockets are container-local — check inside the relevant phpNN container if this host doesn't mount /run/php)"
    fi
  fi
fi

# ---------------------------------------------------------------------------
section "Apache error log"

APACHE_LOG="/var/log/df/apache/error.log"
if [ -r "$APACHE_LOG" ]; then
  info "last $LOG_LINES lines of $APACHE_LOG:"
  tail -n "$LOG_LINES" "$APACHE_LOG" 2>/dev/null | sed 's/^/    /'
  RECENT_ERR_COUNT="$(tail -n 500 "$APACHE_LOG" 2>/dev/null | grep -ciE 'error|segfault|core dumped' || true)"
  if [ "${RECENT_ERR_COUNT:-0}" -gt 20 ]; then
    warn "$RECENT_ERR_COUNT error/segfault lines in the last 500 apache log lines"
  else
    ok "apache error log looks quiet ($RECENT_ERR_COUNT hits in last 500 lines)"
  fi
  if [ -n "$DOMAIN" ]; then
    info "domain-specific matches for '$DOMAIN' (last $LOG_LINES):"
    grep -i "$DOMAIN" "$APACHE_LOG" 2>/dev/null | tail -n "$LOG_LINES" | sed 's/^/    /'
  fi
else
  warn "$APACHE_LOG not readable/missing"
fi

# ---------------------------------------------------------------------------
section "OOM / kernel errors"

OOM_HITS=""
if have journalctl; then
  OOM_HITS="$(journalctl -k --since '24 hours ago' 2>/dev/null | grep -iE 'out of memory|oom-kill|killed process' || true)"
elif have dmesg; then
  OOM_HITS="$(dmesg -T 2>/dev/null | grep -iE 'out of memory|oom-kill|killed process' || true)"
fi
if [ -n "$OOM_HITS" ]; then
  crit "OOM-kill events found in kernel log (last 24h):"
  echo "$OOM_HITS" | tail -n 10 | sed 's/^/    /'
else
  ok "no OOM-kill events in kernel log (last 24h)"
fi

# ---------------------------------------------------------------------------
section "Docker disk usage"
if have docker && docker info >/dev/null 2>&1; then
  docker system df 2>/dev/null | sed 's/^/  /'
fi

# ---------------------------------------------------------------------------
section "Malware / webshell diagnostics"

# 1. Generic discovery of whatever security tooling is actually installed —
#    do NOT probe for specific AV binaries one by one (clamscan/imunify.../maldet...),
#    that just produces a wall of "command not found" before anything useful happens.
AV_PKGS=""
have rpm && AV_PKGS+="$(rpm -qa 2>/dev/null | grep -iE 'clam|imunify|maldet|rkhunter|chkrootkit|sophos|bitdefender|escan')"$'\n'
have dpkg && AV_PKGS+="$(dpkg -l 2>/dev/null | grep -iE 'clam|imunify|maldet|rkhunter|chkrootkit')"$'\n'
AV_UNITS=""
have systemctl && AV_UNITS="$(systemctl list-unit-files 2>/dev/null | grep -iE 'clam|imunify|malware|antivirus|security')"
AV_CRON="$(ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null | grep -iE 'av|malware|scan|imunify|clam')"
AV_PKGS="$(printf '%s' "$AV_PKGS" | sed '/^[[:space:]]*$/d')"

if [ -n "$AV_PKGS" ] || [ -n "$AV_UNITS" ] || [ -n "$AV_CRON" ]; then
  ok "installed AV/security tooling detected:"
  [ -n "$AV_PKGS" ]  && echo "$AV_PKGS"  | sed 's/^/    pkg:  /'
  [ -n "$AV_UNITS" ] && echo "$AV_UNITS" | sed 's/^/    unit: /'
  [ -n "$AV_CRON" ]  && echo "$AV_CRON"  | sed 's/^/    cron: /'
else
  warn "no known AV/security tooling detected (clamav/imunify/maldet/rkhunter/chkrootkit) — relying on signature checks below"
fi

# 2. Portable signature/heuristic checks — work regardless of what (if any) AV is installed
if [ -z "$WEBROOT" ]; then
  for cand in /var/www/vhosts /var/www /kunden /srv/www /data/web; do
    [ -d "$cand" ] && { WEBROOT="$cand"; break; }
  done
fi

if [ -n "$WEBROOT" ] && [ -d "$WEBROOT" ]; then
  SCAN_DIR="$WEBROOT"
  [ -n "$DOMAIN" ] && [ -d "$WEBROOT/$DOMAIN" ] && SCAN_DIR="$WEBROOT/$DOMAIN"
  info "scanning webroot: $SCAN_DIR (can take a while on large trees)"

  OBFUSC_HITS="$(grep -rlE 'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13)' --include='*.php' "$SCAN_DIR" 2>/dev/null | head -n 50)"
  if [ -n "$OBFUSC_HITS" ]; then
    crit "obfuscated eval() pattern found in:"
    echo "$OBFUSC_HITS" | sed 's/^/    /'
  else
    ok "no obfuscated eval(base64_decode/gzinflate/str_rot13) patterns found"
  fi

  BACKDOOR_HITS="$(grep -rlE '(system|exec|passthru|shell_exec|proc_open|assert)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)' --include='*.php' "$SCAN_DIR" 2>/dev/null | head -n 50)"
  if [ -n "$BACKDOOR_HITS" ]; then
    crit "possible webshell pattern (shell-exec fed directly by user input) found in:"
    echo "$BACKDOOR_HITS" | sed 's/^/    /'
  else
    ok "no direct shell-exec-from-user-input patterns found"
  fi

  RECENT_PHP="$(find "$SCAN_DIR" -iname '*.php' -newermt "-${SCAN_DAYS} days" -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -r | head -n 30)"
  if [ -n "$RECENT_PHP" ]; then
    warn "PHP files modified in the last ${SCAN_DAYS} day(s) (review if unexpected):"
    echo "$RECENT_PHP" | sed 's/^/    /'
  else
    ok "no PHP files modified in the last ${SCAN_DAYS} day(s)"
  fi

  UPLOAD_PHP="$(find "$SCAN_DIR" -type d -iname 'uploads' -exec find {} -iname '*.php' \; 2>/dev/null | head -n 30)"
  if [ -n "$UPLOAD_PHP" ]; then
    crit "PHP files found inside uploads/ directories (should never be executable there):"
    echo "$UPLOAD_PHP" | sed 's/^/    /'
  else
    ok "no PHP files found under uploads/ directories"
  fi

  WORLD_WRITABLE="$(find "$SCAN_DIR" -iname '*.php' -perm -0002 2>/dev/null | head -n 30)"
  if [ -n "$WORLD_WRITABLE" ]; then
    warn "world-writable PHP files found (review permissions):"
    echo "$WORLD_WRITABLE" | sed 's/^/    /'
  else
    ok "no world-writable PHP files found"
  fi
else
  warn "no webroot found/specified — skipping content scan (pass one as 2nd argument, e.g. ./df_host_diagnostics.sh <domain> /var/www/vhosts/<domain>)"
fi

# 3. Suspicious cron / process patterns — independent of webroot
SUS_CRON="$(find /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /var/spool/cron -type f 2>/dev/null \
  -exec grep -HniE 'base64|wget[^|]*\|[[:space:]]*(ba)?sh|curl[^|]*\|[[:space:]]*(ba)?sh|/tmp/[a-zA-Z0-9._-]+\.(sh|py|pl)' {} + 2>/dev/null)"
if [ -n "$SUS_CRON" ]; then
  crit "suspicious cron entries (download-and-execute pattern):"
  echo "$SUS_CRON" | sed 's/^/    /'
else
  ok "no suspicious cron entries found"
fi

SUS_PROC="$(ps auxww 2>/dev/null | grep -viE 'grep|ps auxww' | grep -iE '(curl|wget)[^|]*\|[[:space:]]*(ba)?sh|base64 -d|/tmp/[a-zA-Z0-9._-]+\.(sh|py|pl|elf)')"
if [ -n "$SUS_PROC" ]; then
  warn "processes matching suspicious download/exec patterns (review):"
  echo "$SUS_PROC" | sed 's/^/    /'
else
  ok "no obviously suspicious running processes found"
fi

if have ss; then
  info "established outbound connections (review for unexpected destinations):"
  ss -tnp state established 2>/dev/null | head -n 20 | sed 's/^/    /'
fi

# ---------------------------------------------------------------------------
section "Summary"
if [ "$CRIT_COUNT" -eq 0 ] && [ "$WARN_COUNT" -eq 0 ]; then
  printf '  %sAll checks passed.%s\n' "$C_GRN" "$C_RESET"
else
  printf '  %d critical, %d warning issue(s) found:\n' "$CRIT_COUNT" "$WARN_COUNT"
  for issue in "${ISSUES[@]}"; do
    printf '    - %s\n' "$issue"
  done
fi

[ "$CRIT_COUNT" -gt 0 ] && exit 2
[ "$WARN_COUNT" -gt 0 ] && exit 1
exit 0
