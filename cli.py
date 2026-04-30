from __future__ import annotations

import argparse
import json
from pathlib import Path

from core import service


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Duplicate finder CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(s):
        s.add_argument("--report-dir", default="reports")
        s.add_argument("--db", default="reports/scan.db")
        s.add_argument("--json", action="store_true", dest="as_json")

    s = sub.add_parser("scan", help="Scan roots into sqlite cache")
    s.add_argument("roots", nargs="+", type=Path)
    s.add_argument("--compare", action="store_true")
    s.add_argument("--exclude", action="append", default=[])
    s.add_argument("--min-size", type=int, default=1)
    s.add_argument("--follow-symlinks", action="store_true")
    add_common(s)

    d = sub.add_parser("dupes", help="List duplicate groups from db")
    d.add_argument("--compare", action="store_true")
    add_common(d)

    pp = sub.add_parser("plan-prune", help="Build prune plan from dupes")
    pp.add_argument("--compare", action="store_true")
    pp.add_argument("--dry-run", action="store_true", default=True)
    pp.add_argument("--no-dry-run", action="store_false", dest="dry_run")
    add_common(pp)

    ap = sub.add_parser("apply-prune", help="Apply prune plan")
    ap.add_argument("--plan", default="reports/prune_plan.json")
    ap.add_argument("--dry-run", action="store_true", default=True)
    ap.add_argument("--no-dry-run", action="store_false", dest="dry_run")
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--audit-log", default="reports/prune_audit.jsonl")
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--policy", default="config/protection.toml")

    r = sub.add_parser("report", help="Write report artifacts")
    r.add_argument("--compare", action="store_true")
    r.add_argument("--exclude", action="append", default=[])
    add_common(r)

    return p


def _emit(data, as_json: bool):
    if as_json:
        print(json.dumps(data, indent=2))
    else:
        if isinstance(data, dict):
            for k, v in data.items():
                if k == "actions":
                    print(f"actions: {len(v)}")
                else:
                    print(f"{k}: {v}")
        else:
            print(data)


def main() -> int:
    args = _parser().parse_args()

    if args.cmd == "scan":
        report_dir = Path(args.report_dir)
        db = Path(args.db)
        report_dir.mkdir(parents=True, exist_ok=True)
        stats = service.scan_to_db(
            roots=args.roots,
            db_path=db,
            excludes=set(args.exclude),
            follow_symlinks=args.follow_symlinks,
            min_size=args.min_size,
            compare_mode=args.compare,
            scan_error_log_path=report_dir / "scan_errors.txt",
        )
        _emit({"db": str(db), "scan_stats": stats}, args.as_json)
        return 0

    if args.cmd == "dupes":
        groups = service.load_dupes(Path(args.db), compare_mode=args.compare)
        payload = {"group_count": len(groups), "groups": service.serialize_dupes(groups)}
        _emit(payload, args.as_json)
        return 0

    if args.cmd == "plan-prune":
        groups = service.load_dupes(Path(args.db), compare_mode=args.compare)
        plan = service.plan_prune(groups, source_id=str(Path(args.db)))
        plan_path = Path(args.report_dir) / "prune_plan.json"
        plan_path.parent.mkdir(parents=True, exist_ok=True)
        plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        _emit({"plan": str(plan_path), **plan}, args.as_json)
        return 0

    if args.cmd == "apply-prune":
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        result = service.apply_prune(
            plan,
            dry_run=args.dry_run,
            yes=args.yes,
            audit_log=Path(args.audit_log),
            policy_path=Path(args.policy),
        )
        _emit(result, args.as_json)
        return 0

    if args.cmd == "report":
        groups = service.load_dupes(Path(args.db), compare_mode=args.compare)
        stats = {"dupe_groups": len(groups)}
        service.write_reports(Path(args.report_dir), groups, stats, set(args.exclude))
        _emit({"report_dir": args.report_dir, "dupe_groups": len(groups)}, args.as_json)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
