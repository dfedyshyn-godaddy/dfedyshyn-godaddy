# Web hosting malware scan

Two equivalent, portable scripts for a quick virus/malware check on a Linux
web hosting server — a bash version (`web_malware_scan.sh`) and a Python 3
stdlib-only version (`web_malware_scan.py`). Pick whichever fits your
environment; both implement the same checks and CLI. Run either one directly
on the target host — neither SSHes anywhere itself.

## What they do

1. **Discover installed AV / rootkit tooling** instead of assuming one
   specific product is present: `clamscan`, `clamdscan`, `maldet`/`lmd`,
   `rkhunter`, `chkrootkit`, `lynis`, `aide`, `tripwire`, `ossec-control`.
   With `--run-av`, they actually invoke whatever was found against the web
   content roots.
2. **Always run a dependency-free heuristic sweep**, so the check still
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
# bash
./web_malware_scan.sh                 # discovery + heuristic sweep (safe, read-only, fast)
./web_malware_scan.sh --run-av        # also run any AV/rootkit tools found, against web roots
./web_malware_scan.sh --days 7        # widen the "recently changed" window (default 3)
./web_malware_scan.sh --root /path    # add an extra web content root to scan

# python (3.6+, no third-party dependencies)
./web_malware_scan.py                 # same flags as above
./web_malware_scan.py --run-av
./web_malware_scan.py --days 7
./web_malware_scan.py --root /path
```

Some checks (cron inspection, full permission/process visibility) need root;
both scripts warn and continue with what's available otherwise.

## Output

A timestamped report is written to `/tmp/web_malware_scan_<host>_<timestamp>.log`
and mirrored to stdout.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Nothing suspicious found |
| `1`  | Findings present — review the report |
| `2`  | Usage error |
