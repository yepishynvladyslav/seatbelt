#!/usr/bin/env python3
"""
Seatbelt: a safety layer for AI coding agents.

Checks every shell command an agent wants to run. Catastrophic commands are
blocked, irreversible ones need a human "yes", everything is logged.

Works as:
  * a Claude Code PreToolUse hook      (seatbelt hook)
  * a command checker                  (seatbelt check "rm -rf /")
  * a guarded runner for any agent     (seatbelt run -- <command>)

Single file, no dependencies, Python 3.8+. MIT license.
"""
import json
import os
import re
import shlex
import subprocess
import sys
import time

__version__ = "0.3.0"

ALLOW, ASK, BLOCK = "allow", "ask", "block"
RANK = {ALLOW: 0, ASK: 1, BLOCK: 2}

# --------------------------------------------------------------------------- rules
# Each rule: (id, level, regex, why). Regexes run case-insensitively on the
# whole command line, after whitespace is normalised.
RULES = [
    # ---- catastrophic: always blocked
    ("disk-wipe", BLOCK, r"\bmkfs(\.\w+)?\b|\bdd\b[^|;&]*\bof=/dev/(sd|nvme|hd|disk|xvd|vd)|>\s*/dev/(sd|nvme|hd|disk)\w*",
     "Writes directly to a disk device. This destroys data."),
    ("fork-bomb", BLOCK, r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
     "Fork bomb. Freezes the machine."),
    ("chmod-root", BLOCK, r"\bchmod\s+(-\w+\s+)*-R\s+(-\w+\s+)*[0-7]{3,4}\s+(/|~|~/|\$HOME/?)(\s|$)|\bchmod\s+(-[a-z]*\s+)*-?R?\s*[0-7]*777\s+/(\s|$)|\bchown\s+-R\s+\S+\s+(/|~|\$HOME)(\s|$)",
     "Changes permissions on the whole filesystem."),
    ("pipe-to-shell", BLOCK, r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?python[0-9.]*\b",
     "Downloads code from the internet and runs it without review."),
    ("decode-to-shell", BLOCK, r"\b(base64|xxd|openssl)\b[^|;&]*(-d|--decode|-r|enc\s+-d)[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b",
     "Decodes hidden text and runs it as a script. A classic way to sneak a command past a filter."),
    ("env-exfil", BLOCK, r"(^|[;&|]\s*)(env|printenv|set|export\s+-p)\b[^;&]*\|\s*(curl|wget|nc|ncat|socat|ssh|scp)\b",
     "Sends every environment variable, API keys included, to another machine."),
    ("secret-exfil", BLOCK, r"\b(curl|wget|nc|ncat|scp|rsync|ftp)\b.*(\.env\b|id_rsa|id_ed25519|\.ssh/|\.aws/credentials|\.netrc|\.npmrc|\.pypirc)",
     "Sends secrets (keys, .env, credentials) to another machine."),

    # ---- irreversible: needs a human yes
    ("git-force-push", ASK, r"\bgit\s+push\b.*(\s--force(-with-lease)?\b|\s-f\b|\s\+\S+|\s--mirror\b|\s--prune\b)",
     "Force push rewrites shared history. Other people's work can be lost."),
    ("git-hard-reset", ASK, r"\bgit\s+reset\s+.*--hard\b|\bgit\s+reset\s+--hard\b",
     "Throws away uncommitted work."),
    ("git-clean", ASK, r"\bgit\s+clean\s+(-\w*f\w*)",
     "Deletes untracked files permanently."),
    ("git-branch-delete", ASK, r"\bgit\s+branch\s+(-D|--delete\s+--force)\b|\bgit\s+push\s+\S+\s+--delete\b|\bgit\s+push\s+\S+\s+:\S+",
     "Deletes a branch, possibly with unmerged work."),
    ("git-discard", ASK, r"\bgit\s+(checkout|restore)\s+(--\s+)?\.(\s|$)|\bgit\s+stash\s+(drop|clear)\b",
     "Discards local changes."),
    ("sql-drop", ASK, r"\bdrop\s+(table|database|schema|index|view|collection)\b|\bdropdb\b|\.drop\(\)|\bdropDatabase\(",
     "Drops database objects. Data is gone unless you have a backup."),
    ("sql-truncate", ASK, r"\btruncate\s+(table\s+)?\w+",
     "Empties a table."),
    ("sql-delete-all", ASK, r"\bdelete\s+from\s+[\w.\"`]+\s*(;|\"|'|$)|\bdeleteMany\(\s*\{\s*\}\s*\)",
     "DELETE without WHERE removes every row."),
    ("sql-alter-drop", ASK, r"\balter\s+table\s+\S+\s+drop\b",
     "Drops a column or constraint."),
    ("db-reset", ASK, r"\bprisma\s+migrate\s+reset\b|\bdb:(drop|reset|purge)\b|\bmanage\.py\s+flush\b|\balembic\s+downgrade\b|\bmigrate:(fresh|reset|rollback)\b|\bredis-cli\b.*\bflush(all|db)\b|\bFLUSHALL\b",
     "Resets or rolls back a database."),
    ("infra-destroy", ASK, r"\bterraform\s+(destroy|apply\b.*-auto-approve)|\bpulumi\s+destroy\b|\bcdk\s+destroy\b|\bkubectl\s+delete\b|\bhelm\s+(uninstall|delete)\b",
     "Destroys or changes live infrastructure."),
    ("cloud-delete", ASK, r"\b(aws|gcloud|az|doctl|flyctl|fly|heroku)\b.*\b(delete|destroy|terminate|remove|rm|rb)\b",
     "Deletes cloud resources."),
    ("docker-prune", ASK, r"\bdocker\s+(system|volume|image)\s+prune\b|\bdocker\s+volume\s+rm\b|\bdocker\s+compose\s+down\b.*\s-v\b",
     "Deletes Docker data or volumes."),
    ("publish", ASK, r"\bnpm\s+publish\b|\bpnpm\s+publish\b|\byarn\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bgem\s+push\b|\bpoetry\s+publish\b",
     "Publishes a package publicly. Versions can't be taken back."),
    ("prod-deploy", ASK, r"\bvercel\b.*--prod\b|\bnetlify\s+deploy\b.*--prod\b|\bfly(ctl)?\s+deploy\b|\bgit\s+push\s+heroku\b|\bfirebase\s+deploy\b",
     "Deploys to production."),
    ("sudo", ASK, r"(^|[;&|]\s*)sudo\b",
     "Runs with root privileges."),
    ("read-secrets", ASK, r"\b(cat|less|more|head|tail|bat|type)\b[^|;&]*(\.env\b|id_rsa|id_ed25519|\.aws/credentials|\.netrc)|\bprintenv\b|(^|[;&|]\s*)env(\s*$|\s*[|;&])",
     "Prints secrets into the agent's context."),
    ("find-delete", ASK, r"\bfind\b[^|;&]*(\s-delete\b|\s-exec(dir)?\s+(sudo\s+)?(rm|shred|unlink)\b)",
     "find that deletes every file it matches."),
    ("empty-file", ASK, r"(^|[;&|]\s*)(:\s*)?>\s*[^>&\s]+|\btruncate\s+(-\w+\s+)*(-s|--size)\s*=?\s*0\b|\bcp\s+/dev/null\s+\S+|\bdd\b[^|;&]*\bif=/dev/(zero|urandom|random)\b[^|;&]*\bof=",
     "Empties or overwrites a file. If it's a database or a key, the data is gone."),
    ("move-to-null", ASK, r"\bmv\b[^|;&]*\s/dev/null(\s|$)",
     "Moving something into /dev/null destroys it."),
    ("rsync-delete", ASK, r"\brsync\b[^|;&]*\s--delete(-\w+)?\b",
     "rsync --delete removes everything in the destination that isn't in the source."),
    ("shred", ASK, r"\bshred\b|\bsrm\b|\bwipe\b\s+-",
     "Securely destroys files. There is no undo."),
    ("crontab-remove", ASK, r"\bcrontab\s+(-\w*r\w*)\b",
     "Deletes every scheduled job for this user."),
    ("docker-rm", ASK, r"\bdocker\s+(rm|rmi|container\s+rm|image\s+rm)\s+(-\w*f\w*|--force)\b|\bdocker\s+(kill|stop)\s+\$\(",
     "Force-removes Docker containers or images."),
    ("erase-history", ASK, r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|(\.bash_history|\.zsh_history)\b[^|;&]*$|\bHISTSIZE=0\b",
     "Erases the shell history, which is part of the audit trail."),
    ("var-command", ASK, r"(^|[;&|]\s*)\$\{?\w+\}?(\s|$)",
     "Runs a command whose name is hidden in a variable."),
    ("kill-all", ASK, r"\bkillall\b|\bpkill\s+-9\b|\bkill\s+-9\s+-1\b|\bshutdown\b|\breboot\b",
     "Kills processes or shuts the machine down."),
]

RM_SAFE_TARGETS = re.compile(r"^(\./)?(node_modules|dist|build|out|\.next|\.nuxt|\.turbo|\.cache|coverage|target|__pycache__|\.pytest_cache|\.venv|venv|tmp)/?$")
RM_DANGER_TARGETS = re.compile(r"^(/|/\*|~|~/|~/\*|\$HOME/?|\$HOME/\*|\*|\.|\./|\./\*|\.\.|\.\./?|/(etc|usr|var|bin|lib|boot|home|root|opt|srv)/?)$")


def _rm_verdict(cmd):
    """rm needs real parsing: flags can be combined (-rf, -fr, -Rf, --recursive)."""
    results = []
    for part in re.split(r"[;&|]+|\bthen\b|\bdo\b", cmd):
        try:
            toks = shlex.split(part, posix=True)
        except ValueError:
            toks = part.split()
        while toks and toks[0] in ("sudo", "command", "nice", "time", "xargs", "env"):
            toks = toks[1:]
        if not toks or os.path.basename(toks[0]) != "rm":
            continue
        flags = [t for t in toks[1:] if t.startswith("-")]
        targets = [t for t in toks[1:] if not t.startswith("-")]
        recursive = any(f == "--recursive" or (not f.startswith("--") and re.search(r"[rR]", f)) for f in flags)
        if not recursive:
            continue
        if targets and all(RM_SAFE_TARGETS.match(t) for t in targets):
            continue  # build output and caches are safe to delete
        if not targets or any(RM_DANGER_TARGETS.match(t) for t in targets) or "--no-preserve-root" in flags:
            results.append(("rm-root", BLOCK, "Recursive delete of the root, home or current directory."))
        else:
            results.append(("rm-recursive", ASK, "Recursive delete: " + " ".join(targets[:3])))
    return results


# --------------------------------------------------------------------------- config
def _load_config(cwd=None):
    """Optional .seatbelt.json in the project or home dir:
    {"allow": ["regex"], "ask": ["regex"], "block": ["regex"]}"""
    cfg = {"allow": [], "ask": [], "block": [], "mode": "enforce"}
    paths = [os.path.expanduser("~/.seatbelt.json")]
    if cwd:
        paths.append(os.path.join(cwd, ".seatbelt.json"))
    for p in paths:
        try:
            with open(p) as f:
                data = json.load(f)
            for k in ("allow", "ask", "block"):
                cfg[k] += list(data.get(k, []))
            if data.get("mode") in ("enforce", "shadow"):
                cfg["mode"] = data["mode"]
        except (OSError, ValueError):
            pass
    if os.environ.get("SEATBELT_MODE") in ("enforce", "shadow"):
        cfg["mode"] = os.environ["SEATBELT_MODE"]
    return cfg


SHELLS = r"(?:ba|z|da|k|fi)?sh"
SCRIPT_MAX = 256 * 1024

# ---- files that keep Seatbelt itself switched on: an agent must not edit them silently
PROTECTED = re.compile(r"(^|/)\.claude/settings(\.local)?\.json$|(^|/)\.seatbelt\.json$|(^|/)seatbelt\.py$|(^|/)\.seatbelt/")
PROTECTED_IN_CMD = re.compile(r"\.claude/settings(\.local)?\.json|\.seatbelt\.json|\bseatbelt\.py\b|\.seatbelt/")
READ_ONLY_CMD = re.compile(r"^\s*(cat|less|more|head|tail|bat|grep|rg|ls|stat|wc|diff|git\s+(diff|status|log|show)|jq\s+[^>]*$)\b")

# ---- interpreter one-liners: python -c, node -e, ruby -e, perl -e, php -r, deno eval, bun -e
INTERP = re.compile(r"\b(python[0-9.]*|node|nodejs|ruby|perl|php|deno\s+eval|bun)\s+(?:-\w+\s+)*?(-c|-e|-r|--eval|eval)\s+(\"(?:[^\"\\]|\\.)*\"|'[^']*')|\bdeno\s+eval\s+(\"(?:[^\"\\]|\\.)*\"|'[^']*')")
DELETE_API = re.compile(r"shutil\.rmtree|os\.(remove|unlink|rmdir|removedirs)\b|\.unlink\(|\.rmdir\(|send2trash|"
                        r"fs\.(rmSync|rm|rmdirSync|rmdir|unlinkSync|unlink)\b|\.(rmSync|rmdirSync|unlinkSync)\(|rimraf|"
                        r"FileUtils\.(rm_rf|rm_r|remove_dir|rm)|File\.delete|Dir\.delete|\brmtree\b|\bunlink\s*\(|\bunlink\b|\brmdir\b")
DANGER_ARG = re.compile(r"(['\"])(/|~|~/|/home/?|/root/?|/etc/?|/usr/?|/var/?|\.|\./|\$HOME)\1|expanduser\(\s*['\"]~|Path\.home\(\)|os\.homedir\(\)|"
                        r"environ\[['\"]HOME['\"]\]|getenv\(['\"]HOME['\"]\)|ENV\[['\"]HOME['\"]\]|process\.env\.HOME")


def _interp_verdicts(cmd, cwd, depth):
    hits = []
    for m in INTERP.finditer(cmd):
        code = m.group(3) or m.group(4) or ""
        code = code[1:-1]
        if DELETE_API.search(code):
            if DANGER_ARG.search(code):
                hits.append(("interp-delete-root", BLOCK, "A script one-liner deletes the root or home directory."))
            else:
                hits.append(("interp-delete", ASK, "A script one-liner deletes files."))
        # shell commands passed from inside the code: os.system("..."), subprocess.run("..."), execSync("...")
        if depth < 3:
            for lit in re.findall(r"\"((?:[^\"\\]|\\.)*)\"|'([^']*)'", code):
                s = lit[0] or lit[1]
                if len(s) > 2:
                    v, rid, why = check(s, cwd, depth + 1)
                    if v != ALLOW:
                        hits.append((rid, v, why + " (run from inside a " + m.group(1).split()[0] + " one-liner)"))
    return hits


def _self_protect(cmd):
    if PROTECTED_IN_CMD.search(cmd) and not READ_ONLY_CMD.search(cmd):
        return [("self-protect", ASK, "Touches the files that keep Seatbelt switched on.")]
    return []


def _inner_commands(cmd):
    """Commands hidden inside other commands: bash -c "...", eval "...", $(...), `...`."""
    out = []
    for m in re.finditer(r"\b(?:" + SHELLS + r"|sudo\s+" + SHELLS + r")\s+(?:-\w+\s+)*-\w*c\w*\s+(\"(?:[^\"\\]|\\.)*\"|'[^']*'|\S+)", cmd):
        out.append(m.group(1))
    for m in re.finditer(r"\beval\s+(\"(?:[^\"\\]|\\.)*\"|'[^']*'|.+)", cmd):
        out.append(m.group(1))
    out += re.findall(r"\$\(([^()]*)\)", cmd) + re.findall(r"`([^`]*)`", cmd)
    return [s[1:-1] if len(s) > 1 and s[0] == s[-1] and s[0] in "\"'" else s for s in out]


def _scripts(cmd, cwd):
    """Local scripts the command runs: bash x.sh, sh x.sh, source x.sh, . x.sh, ./x.sh"""
    paths = []
    for part in re.split(r"[;&|]+", cmd):
        try:
            toks = shlex.split(part)
        except ValueError:
            toks = part.split()
        while toks and toks[0] in ("sudo", "nohup", "time", "nice", "exec"):
            toks = toks[1:]
        if not toks:
            continue
        head = os.path.basename(toks[0])
        if re.fullmatch(SHELLS, head) or head in ("source", "."):
            args = [t for t in toks[1:] if not t.startswith("-")]
            if args and "-c" not in toks[1:]:
                paths.append(args[0])
        elif toks[0].startswith(("./", "/", "../", "~/")) and not re.fullmatch(r"/(usr/)?s?bin/\S+", toks[0]):
            paths.append(toks[0])
    return [os.path.join(cwd or os.getcwd(), os.path.expanduser(p)) for p in paths]


def _expand_vars(cmd):
    """Resolve simple assignments in the same command: X=rm; $X -rf ~  ->  rm -rf ~"""
    env = {}
    for m in re.finditer(r"(?:^|[;&|]\s*|\s)(?:export\s+)?([A-Za-z_]\w*)=(\"[^\"]*\"|'[^']*'|[^\s;&|]*)", cmd):
        v = m.group(2)
        env[m.group(1)] = v[1:-1] if v[:1] in "\"'" else v
    if not env:
        return cmd
    return re.sub(r"\$\{?([A-Za-z_]\w*)\}?", lambda m: env.get(m.group(1), m.group(0)), cmd)


INTERP_NAMES = r"(python[0-9.]*|node|nodejs|ruby|perl|php|bun)"


def _stdin_code(cmd):
    """Code fed through stdin: python3 - <<< "...", echo "..." | sh, printf '...' | python3"""
    out = []
    for m in re.finditer(r"\b(" + SHELLS + r"|" + INTERP_NAMES + r")\b[^|;&<]*<<<\s*(\"(?:[^\"\\]|\\.)*\"|'[^']*')", cmd):
        out.append((m.group(1), m.group(m.lastindex)[1:-1]))
    for m in re.finditer(r"\b(?:echo|printf)\s+(?:-\w+\s+)*(\"(?:[^\"\\]|\\.)*\"|'[^']*')\s*\|\s*(?:sudo\s+)?(" + SHELLS + r"|" + INTERP_NAMES + r")\b", cmd):
        out.append((m.group(2), m.group(1)[1:-1]))
    return out


def check(cmd, cwd=None, _depth=0):
    """Return (verdict, rule_id, why) for a shell command."""
    if not isinstance(cmd, str):
        return BLOCK, "unverifiable", "Seatbelt could not read this command, so it is not allowed."
    norm = " ".join(cmd.strip().split())
    if not norm:
        return ALLOW, None, None
    cfg = _load_config(cwd)
    for rx in cfg["allow"]:
        if re.search(rx, norm, re.I):
            return ALLOW, "user-allow", "Allowed by your .seatbelt.json"
    # text that is only data (commit messages, echo/grep arguments) must not trigger rules
    scan = re.sub(r"(\s-m|\s--message)(=|\s+)(\"[^\"]*\"|'[^']*')", " ", norm)
    scan = re.sub(r"\b(echo|printf|grep|rg|ag)\b(\s+-\w+)*\s+(\"[^\"]*\"|'[^']*')", r"\1 ", scan)
    expanded = _expand_vars(scan)
    if expanded != scan and _depth < 3:
        v, rid, why = check(expanded, cwd, _depth + 1)
        if v != ALLOW:
            return v, rid, why + " (hidden in a variable)"
    hits = list(_rm_verdict(scan)) + _interp_verdicts(norm, cwd, _depth) + _self_protect(norm)
    for target, code in _stdin_code(norm):
        if _depth >= 3:
            break
        if re.fullmatch(SHELLS, target):
            v, rid, why = check(code, cwd, _depth + 1)
        else:
            v, rid, why = check('%s -c "%s"' % (target, code.replace("\\", "\\\\").replace('"', '\\"')), cwd, _depth + 1)
        if v != ALLOW:
            hits.append((rid, v, why + " (piped into " + target + ")"))
    # look inside wrappers (bash -c, eval, $(...)) and into the scripts a command runs
    if _depth < 3:
        for inner in _inner_commands(norm):
            v, rid, why = check(inner, cwd, _depth + 1)
            if v != ALLOW:
                hits.append((rid, v, why + " (hidden inside another command)"))
        for path in _scripts(norm, cwd):
            try:
                if os.path.getsize(path) > SCRIPT_MAX:
                    hits.append(("script-too-big", ASK, "Script is too large to check: " + os.path.basename(path)))
                    continue
                with open(path, errors="replace") as f:
                    body = f.read()
                if "\x00" in body:
                    continue  # compiled binary, not a script
            except OSError:
                if os.path.splitext(path)[1] in (".sh", ".bash", ".zsh") or os.path.basename(path).startswith("."):
                    hits.append(("script-unreadable", ASK, "Can't read the script to check it: " + os.path.basename(path)))
                continue
            for line in body.splitlines():
                line = line.split("#", 1)[0] if not line.lstrip().startswith("#!") else ""
                v, rid, why = check(line, cwd, _depth + 1)
                if v != ALLOW:
                    hits.append((rid, v, why + " (inside " + os.path.basename(path) + ")"))
    for rid, level, rx, why in RULES:
        if re.search(rx, scan, re.I):
            hits.append((rid, level, why))
    for rx in cfg["block"]:
        if re.search(rx, norm, re.I):
            hits.append(("user-block", BLOCK, "Blocked by your .seatbelt.json"))
    for rx in cfg["ask"]:
        if re.search(rx, norm, re.I):
            hits.append(("user-ask", ASK, "Needs approval per your .seatbelt.json"))
    if not hits:
        return ALLOW, None, None
    rid, level, why = max(hits, key=lambda h: RANK[h[1]])
    return level, rid, why


# --------------------------------------------------------------------------- log
LOG_PATH = os.environ.get("SEATBELT_LOG", os.path.expanduser("~/.seatbelt/log.jsonl"))


def _log(cmd, verdict, rule, source, decision=None):
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "source": source, "verdict": verdict,
                                "rule": rule, "decision": decision, "cmd": cmd}) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- output
def _c(code, s):
    return "\033[%sm%s\033[0m" % (code, s) if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else s


ICON = {ALLOW: ("32", "✓ ALLOW"), ASK: ("33", "⚠ ASK  "), BLOCK: ("31", "⛔ BLOCK")}


def _line(verdict, cmd, rule, why):
    code, label = ICON[verdict]
    out = _c(code + ";1", label) + "  " + cmd
    if rule:
        out += "\n         " + _c("2", "%s · %s" % (rule, why))
    return out


# --------------------------------------------------------------------------- commands
def cmd_check(args):
    if not args:
        print("usage: seatbelt check \"<command>\"", file=sys.stderr)
        return 64
    cmd = " ".join(args)
    v, rule, why = check(cmd, os.getcwd())
    print(_line(v, cmd, rule, why))
    return RANK[v]


def _deny(reason):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))
    return 0


FILE_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")


def cmd_hook(_args):
    """Claude Code PreToolUse hook. Reads the tool call JSON on stdin.
    Fails closed: if Seatbelt can't read or check a command, the command is denied.
    Checks Bash commands, and file edits that would switch Seatbelt itself off."""
    try:
        data = json.load(sys.stdin)
    except Exception:
        return _deny("Seatbelt could not read the tool call, so the command is not allowed.")
    try:
        if not isinstance(data, dict):
            return _deny("Seatbelt could not read the tool call, so the command is not allowed.")
        tool, inp = data.get("tool_name"), (data.get("tool_input") or {})
        if tool == "Bash":
            cmd = inp.get("command", "")
            v, rule, why = check(cmd, data.get("cwd"))
        elif tool in FILE_TOOLS:
            path = inp.get("file_path") or inp.get("notebook_path") or ""
            if not isinstance(path, str):
                return _deny("Seatbelt could not read the file path, so the edit is not allowed.")
            cmd = "%s %s" % (tool, path)
            if PROTECTED.search(path.replace("\\", "/")):
                v, rule, why = ASK, "self-protect", "The agent wants to edit a file that keeps Seatbelt switched on."
            else:
                return 0
        else:
            return 0
        mode = _load_config(data.get("cwd"))["mode"]
    except Exception as e:  # any bug in Seatbelt must never mean "allow"
        return _deny("Seatbelt hit an internal error (%s), so the command is not allowed." % type(e).__name__)
    shown = cmd if isinstance(cmd, str) else repr(cmd)
    if mode == "shadow":
        _log(shown, v, rule, "claude-code-hook", "shadow" if v != ALLOW else None)
        return 0  # shadow mode: record what would have happened, change nothing
    _log(shown, v, rule, "claude-code-hook")
    if v == ALLOW:
        return 0  # no decision: Claude Code's normal permission flow applies
    decision = "deny" if v == BLOCK else "ask"
    reason = "Seatbelt %s [%s]: %s" % ("blocked this" if v == BLOCK else "needs your approval", rule, why)
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}))
    return 0


def cmd_run(args):
    """Guarded runner: seatbelt run -- <command ...>"""
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        print("usage: seatbelt run -- <command>", file=sys.stderr)
        return 64
    cmd = args[0] if len(args) == 1 else " ".join(shlex.quote(a) for a in args)
    v, rule, why = check(cmd, os.getcwd())
    if v != ALLOW and _load_config(os.getcwd())["mode"] == "shadow":
        print(_line(v, cmd, rule, why) + "\n         (shadow mode: logged, not enforced)", file=sys.stderr)
        _log(cmd, v, rule, "run", "shadow")
        return subprocess.call(cmd, shell=True)
    if v == BLOCK:
        print(_line(v, cmd, rule, why), file=sys.stderr)
        _log(cmd, v, rule, "run", "refused")
        return 126
    if v == ASK:
        print(_line(v, cmd, rule, why), file=sys.stderr)
        ok = False
        if sys.stdin.isatty():
            try:
                ok = input("         Run it? [y/N] ").strip().lower() in ("y", "yes")
            except EOFError:
                ok = False
        else:
            print("         No human at the keyboard, so the answer is no.", file=sys.stderr)
        _log(cmd, v, rule, "run", "approved" if ok else "declined")
        if not ok:
            return 126
    else:
        _log(cmd, v, rule, "run", "ran")
    return subprocess.call(cmd, shell=True)


def cmd_log(args):
    n = int(args[1]) if len(args) > 1 and args[0] == "-n" else 20
    try:
        with open(LOG_PATH) as f:
            lines = f.readlines()[-n:]
    except OSError:
        print("No log yet (%s)." % LOG_PATH)
        return 0
    for ln in lines:
        e = json.loads(ln)
        code, label = ICON[e["verdict"]]
        print("%s  %s  %s%s" % (e["ts"], _c(code, label), e["cmd"], ("  [" + e["decision"] + "]") if e.get("decision") else ""))
    return 0


MATCHER = "Bash|Edit|Write|MultiEdit|NotebookEdit"


def cmd_install(args):
    """Add the hook to .claude/settings.json (project) or ~/.claude/settings.json (--global)."""
    base = os.path.expanduser("~") if "--global" in args else os.getcwd()
    path = os.path.join(base, ".claude", "settings.json")
    try:
        with open(path) as f:
            settings = json.load(f)
    except (OSError, ValueError):
        settings = {}
    hook_cmd = '"%s" "%s" hook' % (sys.executable, os.path.abspath(__file__))
    pre = settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
    for entry in pre:
        for h in entry.get("hooks", []):
            if "seatbelt" in h.get("command", ""):
                if entry.get("matcher") == MATCHER:
                    print("Seatbelt is already installed in %s" % path)
                    return 0
                entry["matcher"] = MATCHER  # upgrade older installs that only watched Bash
                break
        else:
            continue
        break
    else:
        pre.append({"matcher": MATCHER, "hooks": [{"type": "command", "command": hook_cmd}]})
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")
    print(_c("32;1", "✓ Seatbelt installed") + " in %s\n  Every Bash command Claude Code runs is now checked first,\n  and edits that would switch Seatbelt off need your approval." % path)
    return 0


def cmd_stats(args):
    """Counts from the log: how often Seatbelt allowed, asked, blocked, and how often you said yes."""
    days = int(args[1]) if len(args) > 1 and args[0] == "--days" else 7
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - days * 86400))
    try:
        with open(LOG_PATH) as f:
            rows = [json.loads(l) for l in f if l.strip()]
    except OSError:
        print("No log yet (%s)." % LOG_PATH)
        return 0
    rows = [r for r in rows if r.get("ts", "") >= cutoff]
    n = len(rows)
    if not n:
        print("No commands in the last %d days." % days)
        return 0
    cnt = {k: sum(1 for r in rows if r["verdict"] == k) for k in (ALLOW, ASK, BLOCK)}
    approved = sum(1 for r in rows if r.get("decision") == "approved")
    shadow = sum(1 for r in rows if r.get("decision") == "shadow")
    rules = {}
    for r in rows:
        if r.get("rule"):
            rules[r["rule"]] = rules.get(r["rule"], 0) + 1
    pct = lambda k: 100.0 * k / n
    print("Seatbelt, last %d days: %d commands checked" % (days, n))
    print("  %s %5d  (%.1f%%)" % (_c("32", "✓ allowed"), cnt[ALLOW], pct(cnt[ALLOW])))
    print("  %s %5d  (%.1f%%)" % (_c("33", "⚠ asked  "), cnt[ASK], pct(cnt[ASK])))
    print("  %s %5d  (%.1f%%)" % (_c("31", "⛔ blocked"), cnt[BLOCK], pct(cnt[BLOCK])))
    if cnt[ASK]:
        print("  you said yes to %d of %d asks: the ones you approve are your likely false positives" % (approved, cnt[ASK]))
    if shadow:
        print("  shadow mode: %d would-be stops logged, none enforced" % shadow)
    if rules:
        print("  top rules: " + ", ".join("%s %d" % kv for kv in sorted(rules.items(), key=lambda kv: -kv[1])[:5]))
    return 0


def cmd_rules(_args):
    for rid, level, _rx, why in [("rm-root", BLOCK, "", "Recursive delete of root/home/current dir."),
                                 ("rm-recursive", ASK, "", "Recursive delete of anything else."),
                                 ("interp-delete-root", BLOCK, "", "python -c / node -e / ruby -e deleting root or home."),
                                 ("interp-delete", ASK, "", "python -c / node -e / ruby -e deleting files."),
                                 ("self-protect", ASK, "", "Editing the files that keep Seatbelt switched on.")] + RULES:
        code, label = ICON[level]
        print("%s  %-18s %s" % (_c(code, label), rid, why))
    return 0


HELP = """seatbelt %s: a safety layer for AI coding agents

  seatbelt check "<command>"     check one command (exit 0 allow, 1 ask, 2 block)
  seatbelt run -- <command>      run a command, asking first if it's risky
  seatbelt hook                  Claude Code PreToolUse hook (reads JSON on stdin)
  seatbelt install [--global]    add the hook to .claude/settings.json
  seatbelt log [-n 20]           show recent decisions
  seatbelt stats [--days 7]      how often it allowed, asked, blocked
  seatbelt rules                 list built-in rules

  SEATBELT_MODE=shadow           log what would be stopped, enforce nothing
""" % __version__


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(HELP)
        return 0
    if argv[0] in ("-V", "--version"):
        print(__version__)
        return 0
    cmds = {"check": cmd_check, "hook": cmd_hook, "run": cmd_run, "log": cmd_log,
            "install": cmd_install, "rules": cmd_rules, "stats": cmd_stats}
    fn = cmds.get(argv[0])
    if not fn:
        print(HELP, file=sys.stderr)
        return 64
    return fn(argv[1:])


if __name__ == "__main__":
    sys.exit(main())
