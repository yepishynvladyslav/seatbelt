# 🛡️ Seatbelt

**A safety layer for AI coding agents.**
Your agent can write code all night. It can't delete your database.

Seatbelt checks every shell command an AI agent wants to run *before* it runs:

- ⛔ **Catastrophic commands are blocked.** `rm -rf /`, wiping disks, `curl … | bash`, sending your `.env` or SSH keys to another machine.
- ⚠️ **Irreversible commands need a human "yes".** Force pushes, `DROP TABLE`, `DELETE` without `WHERE`, `terraform destroy`, `kubectl delete`, `npm publish`, production deploys.
- ✅ **Everything else runs normally,** and every decision is logged.

One Python file. No dependencies. Works with **Claude Code** out of the box, and with any other agent through `seatbelt run`.

```
$ seatbelt check "rm -rf ~"
⛔ BLOCK  rm -rf ~
         rm-root · Recursive delete of the root, home or current directory.

$ seatbelt check "psql -c 'DROP TABLE users;'"
⚠ ASK    psql -c 'DROP TABLE users;'
         sql-drop · Drops database objects. Data is gone unless you have a backup.

$ seatbelt check "npm test"
✓ ALLOW  npm test
```

## Why

AI agents now run real commands on real machines. In July 2025, an AI coding agent deleted a company's production database during a code freeze. The agent wasn't evil. Nothing stood between "the agent decided" and "the command ran".

Seatbelt is that something.

## Install

```bash
pip install git+https://github.com/yepishynvladyslav/seatbelt
```

Or grab the single file:

```bash
curl -fsSLO https://raw.githubusercontent.com/yepishynvladyslav/seatbelt/main/seatbelt.py
python3 seatbelt.py --help
```

(Read it first. It's one file, about 300 lines. Seatbelt itself would ask you to.)

## Use with Claude Code (30 seconds)

In your project folder:

```bash
seatbelt install            # this project only
seatbelt install --global   # every project
```

This adds a `PreToolUse` hook to `.claude/settings.json`. From now on, every Bash command Claude Code wants to run goes through Seatbelt first:

| Seatbelt says | Claude Code does |
|---|---|
| ⛔ block | The command is denied, and Claude is told why |
| ⚠️ ask | You get asked to approve it, even in auto-accept mode |
| ✅ allow | Normal flow, nothing changes |

Prefer to edit the file yourself? See [`examples/claude-settings.json`](examples/claude-settings.json).

## Use with any other agent

Point your agent's shell tool at `seatbelt run`:

```bash
seatbelt run -- "git push --force origin main"
⚠ ASK    git push --force origin main
         git-force-push · Force push rewrites shared history. Other people's work can be lost.
         Run it? [y/N]
```

With no human at the keyboard (CI, background agents), anything risky gets an automatic **no**.

## See what your agent tried to do

```bash
$ seatbelt log
2026-11-09T03:12:08  ✓ ALLOW  npm test  [ran]
2026-11-09T03:14:51  ⚠ ASK    git push --force  [declined]
2026-11-09T03:15:02  ⛔ BLOCK  rm -rf ~  [refused]
```

Logs live in `~/.seatbelt/log.jsonl` (change it with `SEATBELT_LOG`).

## Your own rules

Drop a `.seatbelt.json` in your project (or `~/.seatbelt.json`):

```json
{
  "allow": ["^rm -rf (dist|build|node_modules)$"],
  "ask":   ["\\bstripe\\b.*\\brefunds\\b"],
  "block": ["\\bdeploy-prod\\.sh\\b"]
}
```

Values are regular expressions. `allow` wins, then the strictest match.

## Built-in rules

```bash
seatbelt rules
```

**Blocked:** recursive delete of `/`, `~`, `.` or `*` · disk wipes (`mkfs`, `dd of=/dev/…`) · fork bombs · `chmod -R 777 /` · piping downloads into a shell · sending `.env`, SSH keys or cloud credentials over the network.

**Ask first:** other recursive deletes (build folders like `node_modules`, `dist`, `build` are fine) · `git push --force` · `git reset --hard` · `git clean -f` · deleting branches · discarding changes · `DROP` / `TRUNCATE` / `DELETE` without `WHERE` · database resets and rollbacks · `terraform destroy` · `kubectl delete` · cloud deletes (AWS, GCP, Azure, Fly, Heroku…) · Docker prunes · `npm publish` and other package publishes · production deploys · `sudo` · printing secrets into the agent's context · `killall` / `shutdown`.

## Honest limits

Seatbelt is a seatbelt, not a crash-proof car.

- **Fails closed.** If Seatbelt can't read or check a command (bad input, internal error), the hook denies it. A broken checker never means "allow".
- **Looks inside wrappers.** `bash -c "…"`, `sh -c`, `eval`, `$(…)` and `base64 -d | sh` are unwrapped and checked. Local scripts the command runs (`bash x.sh`, `./x.sh`, `source x.sh`) are read and checked line by line. A script it can't read needs your approval.
- It still reads command text. A determined agent can hide intent in ways no text filter catches (a Python one-liner that deletes files, a script it writes and runs in two steps). Seatbelt catches the common, accidental disasters, not a deliberate attacker.
- Use it **together with** backups, least-privilege credentials, and separate dev/prod access.
- Found a dangerous command it misses, or a safe one it flags? Open an issue or a PR. Rules are plain regexes with tests.

## Develop

```bash
python3 -m unittest -v
```

## License

MIT
