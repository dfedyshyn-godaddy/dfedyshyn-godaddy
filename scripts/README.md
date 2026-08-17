# web_malware_scan.sh

Portable bash script for a quick virus/malware check on a Linux web hosting
server. Run it directly on the target host — it never SSHes anywhere itself.

## What it does

1. **Discovers installed AV / rootkit tooling** instead of assuming one
   specific product is present: `clamscan`, `clamdscan`, `maldet`/`lmd`,
   `rkhunter`, `chkrootkit`, `lynis`, `aide`, `tripwire`, `ossec-control`.
   With `--run-av`, it actually invokes whatever it found against the web
   content roots.
2. **Always runs a dependency-free heuristic sweep**, so the check still
   works on boxes with no AV installed at all:
   - recently modified script files (`.php`, `.cgi`, `.pl`, `.py`, `.sh`)
   - known webshell / obfuscation signatures in PHP content
     (`eval(base64_decode`, `gzinflate`, `c99shell`, `r57shell`, `WSO`, etc.)
   - suspicious double/masked extensions (e.g. `shell.php.jpg`)
   - world-writable files under web roots
   - cron entries that pipe a download straight into a shell
     (`curl ... | bash`, `base64 -d`)
   - running processes matching known miner/backdoor names
     (`xmrig`, `kinsing`, `kdevtmpfsi`, ...)

Web content roots are auto-detected from common hosting layouts
(`/var/www`, `/var/www/html`, `/var/www/vhosts`, `/home/*/htdocs`,
`/home/*/public_html`, `/home/*/www`, `/srv/www`) and can be extended with
`--root`.

## Usage

```bash
./web_malware_scan.sh                 # discovery + heuristic sweep (safe, read-only, fast)
./web_malware_scan.sh --run-av        # also run any AV/rootkit tools found, against web roots
./web_malware_scan.sh --days 7        # widen the "recently changed" window (default 3)
./web_malware_scan.sh --root /path    # add an extra web content root to scan
```

Some checks (cron inspection, full permission/process visibility) need root;
the script warns and continues with what's available otherwise.

## Output

A timestamped report is written to `/tmp/web_malware_scan_<host>_<timestamp>.log`
and mirrored to stdout.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Nothing suspicious found |
| `1`  | Findings present — review the report |
| `2`  | Usage error |
