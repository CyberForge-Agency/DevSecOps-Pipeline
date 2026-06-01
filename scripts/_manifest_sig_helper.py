#!/usr/bin/env python3
"""Tiny JSON-merge helper for seal-evidence.sh.

Usage:
  _manifest_sig_helper.py <manifest.json> set-sig   <name> <key=val>...
  _manifest_sig_helper.py <manifest.json> set-tool  <name> <version>
  _manifest_sig_helper.py <manifest.json> get        <dotted.path>     (prints value)
  _manifest_sig_helper.py <manifest.json> set-worm  <state>
All edits write the manifest back atomically (deterministic 2-space indent).
"""
import json
import sys
from pathlib import Path


def load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def save(p, data):
    text = json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False)
    tmp = Path(str(p) + ".tmp")
    tmp.write_text(text + "\n", encoding="utf-8")
    tmp.replace(p)


def parse_kv(args):
    out = {}
    for a in args:
        if "=" not in a:
            out[a] = True
            continue
        k, v = a.split("=", 1)
        if v in ("true", "false"):
            out[k] = (v == "true")
        else:
            out[k] = v
    return out


def main(argv):
    if len(argv) < 3:
        sys.stderr.write("helper: not enough args\n")
        return 2
    path, cmd = argv[0], argv[1]
    data = load(path)

    if cmd == "set-sig":
        name = argv[2]
        kv = parse_kv(argv[3:])
        sigs = data.setdefault("signatures", {})
        entry = sigs.get(name, {})
        if not isinstance(entry, dict):
            entry = {}
        entry.update(kv)
        sigs[name] = entry
        save(path, data)
        return 0

    if cmd == "set-tool":
        name = argv[2]
        version = argv[3] if len(argv) > 3 else "unknown"
        tooling = data.setdefault("tooling", {})
        tooling[name] = version
        save(path, data)
        return 0

    if cmd == "set-worm":
        data["worm_state"] = argv[2]
        save(path, data)
        return 0

    if cmd == "get":
        cur = data
        for part in argv[2].split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = ""
                break
        if isinstance(cur, (dict, list)):
            sys.stdout.write(json.dumps(cur))
        else:
            sys.stdout.write("" if cur is None else str(cur))
        return 0

    sys.stderr.write(f"helper: unknown command {cmd}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
