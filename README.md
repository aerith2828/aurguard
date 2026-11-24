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
$ aurguard upgrade
someapp-bin 1.4.0-1 -> 1.4.0-2  installed 1.4.0-1 -> AUR 1.4.0-2, 1 commits, maintainer newguy
  MEDIUM  maintainer-changed
          Maintainer changed from olduser to newguy.
  HIGH    known-ioc  PKGBUILD:31
          npm install atomic-lockfile
          Matches a published indicator of the June 2026 AUR malware campaign.
  gemini-4-hydrogen: likely_malicious - prepare() now installs the npm package
          "atomic-lockfile", which has nothing to do with building someapp ...

44 package bases, 1 with findings, 21 quiet

Something was found. Run `paru -Sua` anyway? [y/N]:
```

Nothing from the AUR is ever executed or checked out: package repositories are
kept as bare git clones and files are only read with `git show`.

## Requirements

**Required**

| what | why |
|---|---|
| Arch Linux (or a derivative) with `pacman` | `pacman -Qm` lists the installed AUR packages |
| Python 3.11 or newer | the tool itself; standard library only |
| `git` | fetching AUR package repositories |
| internet access to `aur.archlinux.org` | AUR RPC and git |

**Optional**

| what | for |
|---|---|
| `paru` or `yay` | `aurguard upgrade` (check, then upgrade) |
| `libnotify` (`notify-send`) | desktop notifications |
| `systemd` user session | running `watch` on a timer |
| an API key for Claude, ChatGPT, Gemini, DeepSeek or an OpenAI-compatible server | AI explanations of findings |
| Python packages `anthropic` (Claude) or `openai` (everything else), plus `pydantic` | AI explanations; installed with the `[claude]`, `[openai]` or `[ai]` extra |

## Install

```
git clone https://github.com/aerith2828/aurguard
cd aurguard
uv tool install .              # rules only
uv tool install '.[ai]'        # with AI support for every provider
aurguard setup
```

`pip install .` in a venv or `pipx install .` work too. To run from the
checkout without installing: `python3 -m aurguard check`.

## Setup

`aurguard setup` asks a few questions in the terminal and writes
`~/.config/aurguard/config.toml`:

1. **AUR helper**: paru or yay (detected), and the arguments for upgrades,
   e.g. `-Sua --ignore somepkg`.
2. **AI provider**: none, Claude, ChatGPT, Gemini, DeepSeek or another
   OpenAI-compatible API. Then the model (Enter takes the default), the API
   key, whether to explain findings automatically, and an optional test
   request.
3. **Notifications**: desktop notifications for `watch`, and a webhook URL.
4. **Timer**: optionally installs and enables a systemd user timer that runs
   `aurguard watch` every 6 hours.

The API key can live in the config file (created with mode `600`, plain text)
or in an environment variable, which always wins over the file. When you
switch providers, the stored key is dropped so it is never sent to the wrong
company.

For scripts and dotfiles there is a non-interactive form:

```
aurguard setup --set ai.provider=deepseek --set ai.auto_explain=true
aurguard setup --show            # current settings, key masked
```

## Usage

| command | compares | use it |
|---|---|---|
| `aurguard upgrade` | installed -> AUR, then runs paru/yay | instead of `paru -Sua` / `yay -Sua` |
| `aurguard check` | installed version -> AUR | to look before upgrading yourself |
| `aurguard watch` | last run -> AUR, remembers state | from a timer |
| `aurguard audit` | every file at the AUR head | once, to check what you already have |

Exit status: `0` nothing at or above `--fail-on` (default `high`), `1` findings,
`2` error.

### paru and yay

`aurguard upgrade` works the same with both, because they take the same flags:

```
aurguard upgrade                                  # helper and arguments from setup (default: -Sua)
aurguard upgrade -- -Sua --ignore opentabletdriver
aurguard upgrade --helper yay -- -Sua --devel
```

- Everything after `--` goes to the helper unchanged.
- Packages passed with `--ignore` and packages in `IgnorePkg` in
  `/etc/pacman.conf` are left out of the check, since they won't be upgraded
  anyway. `check` honours `IgnorePkg` too, unless you use `--include-ignored`.
- If nothing reaches `--fail-on`, aurguard replaces itself with the helper, so
  the helper's prompts and review screens work as usual.
- If something does, aurguard asks before going on. Without a terminal it
  stops, unless you pass `--yes`. If the check itself fails (no network,
  AUR down), it never upgrades.

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

## AI explanations

| provider | default model | key from | extra |
|---|---|---|---|
| Claude (Anthropic) | `claude-opus-5-5` | `ANTHROPIC_API_KEY` | `[claude]` |
| ChatGPT (OpenAI) | `gpt-6.2-astra` | `OPENAI_API_KEY` | `[openai]` |
| Gemini (Google) | `gemini-4-hydrogen` | `GEMINI_API_KEY` or `GOOGLE_API_KEY` | `[openai]` |
| DeepSeek | `deepseek-flash` | `DEEPSEEK_API_KEY` | `[openai]` |
| OpenAI-compatible (OpenRouter, Ollama, LM Studio, ...) | you choose | `AURGUARD_API_KEY` (optional for local servers) | `[openai]` |

`AURGUARD_API_KEY` overrides the key for any provider. Gemini is called through
Google's OpenAI-compatible endpoint, so one client library covers everything
except Claude.

Only packages with findings are sent: their diff and the rule hits. The model
answers with a verdict (`looks_benign` / `needs_attention` / `likely_malicious`),
a short summary and the lines that matter. Claude, ChatGPT and Gemini return
schema-validated structured output. DeepSeek and generic servers only offer a
JSON mode, so their answer is validated locally and rejected if it does not
fit. The answer is printed **next to** the rule findings and never replaces
them: the diff was written by whoever pushed to the package, and an attacker
can fill it with comments addressed to the model. The prompt tells the model
to treat such text as a warning sign.

Turn it on for a single run with `--explain`, or always (except for `audit`)
with `ai.auto_explain` from setup. `--no-explain` turns it off for one run.

## Notifications

`watch` shows a desktop notification (`notify-send`) only when something is
found, unless that is turned off in setup. `--webhook URL` (or
`AURGUARD_WEBHOOK`, or `notify.webhook` in the config) posts to Discord, Slack
or ntfy. Any other URL gets JSON with the full report under `"aurguard"`,
which is enough to hook it into n8n or similar.

The systemd units that `setup` installs are also in [`contrib/`](contrib/), if
you prefer to install them by hand.

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
catch it. The AI providers are tested against fake clients, so the tests need
no keys and make no network requests.

MIT licensed.
