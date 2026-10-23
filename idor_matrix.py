#!/usr/bin/env python3
"""idor-matrix — systematic object-level authorisation testing (IDOR/BOLA).

Most IDOR findings are missed because testing is ad-hoc: you poke one ID, it 403s,
you move on. This tool makes the matrix explicit: for every object endpoint, request
*each* ID as *each* account and record who can read what.

Safety defaults:
  * GET only unless --allow-write is passed
  * refuses to run without an explicit --execute (dry-run prints the plan)
  * rate-limited, sequential, and every request logged to the output TSV

Config (YAML):
    base_url: https://target.example
    accounts:
      alice: { headers: { Authorization: "Bearer A" }, ids: [101, 102] }
      bob:   { headers: { Authorization: "Bearer B" }, ids: [201, 202] }
    endpoints:
      - name: invoice
        path: /api/v1/invoices/{id}
      - name: user-profile
        path: /api/v1/users/{id}

Usage:
    idor-matrix plan  -c config.yaml
    idor-matrix run   -c config.yaml --execute -o out.tsv
"""
from __future__ import annotations
import argparse, csv, sys, time
from pathlib import Path

try:
    import yaml
except ImportError:
    print("need PyYAML: pip install pyyaml", file=sys.stderr); raise

try:
    import requests
except ImportError:
    requests = None


# ---------- planning (pure, testable) ----------
def load_config(path: str | Path) -> dict:
    cfg = yaml.safe_load(Path(path).read_text())
    if not isinstance(cfg, dict) or "base_url" not in cfg or "accounts" not in cfg:
        raise ValueError("config needs at least base_url and accounts")
    if not cfg.get("endpoints"):
        raise ValueError("config needs at least one endpoint")
    return cfg


def build_matrix(cfg: dict) -> list[dict]:
    """One row per (endpoint, requester, owner, id). Requesters test every account's ids."""
    rows = []
    accounts = cfg["accounts"]
    for ep in cfg["endpoints"]:
        for req_name, req in accounts.items():
            for owner_name, owner in accounts.items():
                for oid in owner.get("ids", []) or []:
                    rows.append({
                        "endpoint": ep["name"],
                        "path": ep["path"].replace("{id}", str(oid)),
                        "requester": req_name,
                        "owner": owner_name,
                        "object_id": oid,
                        "same_account": req_name == owner_name,
                    })
    return rows


def verdict(row: dict, status: int | None, body_len: int | None, baseline_len: int | None) -> str:
    """Classify one request. Only cross-account rows can be findings."""
    if status is None:
        return "ERROR"
    if row["same_account"]:
        return "baseline_ok" if status == 200 else f"baseline_{status}"
    if status in (401, 403):
        return "denied"
    if status == 404:
        return "not_found"
    if status == 200:
        # same body size as the requester's own object is suspicious for a foreign id
        if baseline_len is not None and body_len == baseline_len:
            return "CHECK_SAME_SIZE"
        return "CANDIDATE_IDOR"
    return f"http_{status}"


# ---------- execution ----------
def run(cfg: dict, allow_write: bool, delay: float) -> list[dict]:
    if requests is None:
        raise RuntimeError("requests not installed: pip install requests")
    rows = build_matrix(cfg)
    methods = ["GET"] + (["PUT", "PATCH", "DELETE"] if allow_write else [])
    results = []
    baselines: dict[tuple[str, str], int] = {}
    for row in rows:
        for method in methods:
            url = cfg["base_url"].rstrip("/") + row["path"]
            headers = dict(cfg["accounts"][row["requester"]].get("headers") or {})
            status = body_len = None
            try:
                r = requests.request(method, url, headers=headers, timeout=20, allow_redirects=False)
                status, body_len = r.status_code, len(r.content)
            except Exception as e:                       # network errors are results too
                results.append({**row, "method": method, "status": None,
                                "bytes": None, "verdict": "ERROR", "note": type(e).__name__})
                continue
            key = (row["requester"], row["endpoint"])
            if row["same_account"] and status == 200:
                baselines.setdefault(key, body_len)
            row_verdict = verdict(row, status, body_len, baselines.get(key))
            results.append({**row, "method": method, "status": status,
                            "bytes": body_len, "verdict": row_verdict, "note": ""})
            time.sleep(delay)
    return results


def summarise(results: list[dict]) -> dict:
    findings = [r for r in results if r["verdict"] == "CANDIDATE_IDOR"]
    checks = [r for r in results if r["verdict"] == "CHECK_SAME_SIZE"]
    errors = [r for r in results if r["verdict"] == "ERROR"]
    return {"requests": len(results), "candidate_idor": findings,
            "same_size_review": checks, "errors": errors}


COLS = ["endpoint", "method", "path", "requester", "owner", "object_id", "status", "bytes", "verdict", "note"]


def write_tsv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS, delimiter="\t", extrasaction="ignore")
        w.writeheader(); w.writerows(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="idor-matrix")
    ap.add_argument("cmd", choices=["plan", "run"])
    ap.add_argument("-c", "--config", required=True)
    ap.add_argument("--execute", action="store_true", help="actually send requests")
    ap.add_argument("--allow-write", action="store_true", help="also try PUT/PATCH/DELETE")
    ap.add_argument("--delay", type=float, default=0.3, help="seconds between requests")
    ap.add_argument("-o", "--out", default="idor-matrix.tsv")
    a = ap.parse_args(argv)

    cfg = load_config(a.config)
    rows = build_matrix(cfg)

    if a.cmd == "plan" or not a.execute:
        print(f"target: {cfg['base_url']}")
        print(f"accounts: {', '.join(cfg['accounts'])}")
        print(f"endpoints: {len(cfg['endpoints'])} · requests to send: {len(rows)}")
        for ep in cfg["endpoints"]:
            print(f"  {ep['name']:<20} {ep['path']}")
        if not a.execute:
            print("\ndry run — nothing sent. add --execute to run.")
        return 0

    results = run(cfg, a.allow_write, a.delay)
    write_tsv(results, Path(a.out))
    s = summarise(results)
    print(f"\n{s['requests']} requests -> {a.out}")
    print(f"candidate IDOR: {len(s['candidate_idor'])}")
    for r in s["candidate_idor"][:10]:
        print(f"  {r['method']} {r['path']}  as {r['requester']} on {r['owner']}'s object ({r['status']})")
    if s["same_size_review"]:
        print(f"same-size (review manually): {len(s['same_size_review'])}")
    if s["errors"]:
        print(f"errors: {len(s['errors'])}")
    print("\nReminder: a 200 is a candidate, not a finding. Confirm foreign data is real, then report.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
