# aurguard

See what changed in the AUR packages you have installed **before** you
upgrade them, and get warned when a change looks like the ones from the
June 2026 AUR malware campaign.

In June 2026 more than 400 AUR packages had `npm install atomic-lockfile` or
`bun install js-digest` slipped into their PKGBUILD or `.install` files, which
dropped an infostealer and an eBPF rootkit on every machine that built them.
AUR helpers do show the diff before building, but after the tenth Electron app
update in a week nobody reads it. aurguard reads it for you and only speaks
up when something is worth a look.

```
$ aurguard check
someapp-bin 1.4.0-1 -> 1.4.0-2  installed 1.4.0-1 -> AUR 1.4.0-2, 1 commits, maintainer newguy
  MEDIUM  maintainer-changed
          Maintainer changed from olduser to newguy.
  HIGH    known-ioc  PKGBUILD:31
          npm install atomic-lockfile
          Matches a published indicator of the June 2026 AUR malware campaign.
  MEDIUM  js-package-manager  PKGBUILD:31
          npm install atomic-lockfile
          Newly fetches packages from the npm registry at build time ...

44 package bases, 1 with findings, 21 quiet
```

Python 3.11+, standard library only. Nothing from the AUR is ever executed or
checked out: package repositories are kept as bare git clones and files are
read with `git show`.

## How it works

1. `pacman -Qm` lists packages that did not come from the official repos.
2. The AUR RPC gives the current version and maintainer of each.
3. The package's git repo is cloned (bare) or fetched into `~/.cache/aurguard`.
4. aurguard finds the commit that matches the version **you have installed**,
   by reading `.SRCINFO` back through the history, and diffs it against the
   AUR head. When several commits carry the same version it takes the oldest,
   so a change pushed without a `pkgrel` bump is still included.
5. Every **added** line goes through a small set of rules. A long-standing
   `npm install` in an Electron package is not reported on every update, only
   when it first appears.

| command | compares | use it |
|---|---|---|
| `aurguard check` | installed version -> AUR | before `paru -Sua` |
| `aurguard watch` | last run -> AUR, remembers state | from a timer, with `--notify` |
| `aurguard audit` | every file at the AUR head | once, to check what you already have |

Exit status: `0` nothing at or above `--fail-on` (default `high`), `1` findings,
`2` error. So `aurguard check && paru -Sua` does what it looks like it does.

## Rules

| rule | severity | catches |
|---|---|---|
| `known-ioc` | high | published indicators of the June 2026 campaign (package names, C2 host, payload hashes) |
| `pipe-to-shell` | high | `curl ... \| sh` and friends |
| `decode-and-run` | high | `base64 -d \| sh`, `eval "$(curl ...)"`, `python -c "exec(...)"` |
| `network-in-install-hook` | high | `curl`, `npm`, `bun`, `pip` ... inside a `.install` file (those run as root) |
| `persistence` | high | `/etc/ld.so.preload`, cron, autostart, writing systemd units |
| `suspicious-host` | high | `.onion`, bare IPs, paste/upload sites, Discord CDN, URL shorteners |
| `js-package-manager` | medium | newly added `npm`/`bun`/`pnpm`/`yarn install` (lockfile-frozen installs excluded) |
| `pip-install`, `sudo-in-build`, `setuid`, `obfuscation` | medium | things a PKGBUILD rarely needs |
| `maintainer-changed`, `adopted` | medium | the package changed hands since the last run |
| `new-host` | info | a download host that was not in the previous version |

The rules are regular expressions in [`aurguard/rules.py`](aurguard/rules.py),
each with a one-line explanation that is printed next to the finding. Against
the 44 AUR packages on my machine, a full `audit` flags one thing: Brave's
setuid `chrome-sandbox`, which is real and expected.

## Optional: ask Claude what a change does

```
pip install 'aurguard[llm]'
export ANTHROPIC_API_KEY=...
aurguard check --explain
```

For packages with findings, the diff and the rule hits are sent to the Claude
API, which answers with a verdict (`looks_benign` / `needs_attention` /
`likely_malicious`), a short summary and the lines that matter. The model's
answer is printed **next to** the rule findings and never replaces them: the
diff was written by whoever pushed to the package, and an attacker can fill
it with comments addressed to the model. The prompt tells the model to treat
such text as a warning sign. Diffs without findings are never sent.

## Running it regularly

```
pip install .                      # or: uv tool install .
cp contrib/aurguard-watch.{service,timer} ~/.config/systemd/user/
systemctl --user enable --now aurguard-watch.timer
```

`watch --notify` shows a desktop notification (`notify-send`) only when
something is found. `--webhook URL` (or `AURGUARD_WEBHOOK`) posts to Discord,
Slack or ntfy. Other URLs get JSON with the full report under `"aurguard"`,
which is enough to hook it into n8n or similar.

[`contrib/paru-guarded.sh`](contrib/paru-guarded.sh) wraps `paru` so that an
upgrade stops when `check` finds something high-severity, or when the check
itself fails.

## What it does not do

- It reads the build recipe, not what the recipe downloads. A malicious
  upstream tarball or a compromised npm dependency of a legitimate app goes
  unnoticed if the PKGBUILD does not change.
- Regular expressions can be evaded by someone who knows them. This is a
  tripwire for the lazy, mass-scale kind of attack, not an antivirus.
- `-git` packages compute their version at build time, so the first run
  scans all their files. Later runs compare against the last-seen commit.

## Tests

```
python3 -m pytest tests      # or: python3 -m unittest discover tests
```

The end-to-end test builds a fake AUR repo where `npm install atomic-lockfile`
is pushed without a version bump, and checks that both `check` and `watch`
catch it.

MIT licensed.
