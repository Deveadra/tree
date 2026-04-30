from __future__ import annotations

import argparse
import json
from pathlib import Path

from core import service
from core.space_audit import (
    diff_space_snapshots,
    resolve_previous_snapshot,
    scan_space_usage,
    summarize_by_extension,
    summarize_top_dirs,
    write_space_reports,
)


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

    w = sub.add_parser("watchdog", help="Sample free-space timeline (read-only)")
    w.add_argument("root", type=Path)
    w.add_argument("--report-dir", default="reports")
    w.add_argument("--interval", type=float, default=1.0)
    w.add_argument("--duration", type=float, default=None)
    w.add_argument("--max-rows", type=int, default=None)
    w.add_argument("--spike-threshold-bytes", type=int, default=None)
    w.add_argument("--json", action="store_true", dest="as_json")

    sa = sub.add_parser("space-audit", help="Run read-only disk usage audit and write reports")
    sa.add_argument("root", type=Path, help="Root path to audit")
    sa.add_argument("--report-dir", default="reports")
    sa.add_argument("--depth", type=int, default=4)
    sa.add_argument("--top-n", type=int, default=50)
    sa.add_argument("--compare-to", type=Path, default=None, help="Optional previous snapshot JSON path")
    sa.add_argument("--watchdog-interval", type=float, default=None)
    sa.add_argument("--watchdog-duration", type=float, default=None)
    sa.add_argument("--exclude", action="append", default=[])
    sa.add_argument("--json", action="store_true", dest="as_json")

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

    if args.cmd == "watchdog":
        try:
            payload = service.run_free_space_watchdog(
                root=args.root,
                report_dir=Path(args.report_dir),
                interval_seconds=args.interval,
                duration_seconds=args.duration,
                max_rows=args.max_rows,
                spike_threshold_bytes=args.spike_threshold_bytes,
                cancel_flag=None,
            )
        except KeyboardInterrupt:
            payload = {
                "root": str(args.root),
                "output_csv": str(Path(args.report_dir) / "free_space_timeline.csv"),
                "cancelled": True,
                "mode": "watchdog_read_only",
            }
        _emit(payload, args.as_json)
        return 0

    if args.cmd == "space-audit":
        report_dir = Path(args.report_dir)
        report_dir.mkdir(parents=True, exist_ok=True)

        snapshot = scan_space_usage(
            root=args.root,
            excludes=args.exclude,
            depth=max(0, int(args.depth)),
            audit_mode=True,
        )
        top_n = max(1, int(args.top_n))
        top_dirs = summarize_top_dirs(snapshot, top_n=top_n)
        by_ext = summarize_by_extension(snapshot, top_n=top_n)

        previous_snapshot = None
        previous_source = None
        if args.compare_to is not None:
            previous_source = str(args.compare_to)
            previous_snapshot = json.loads(args.compare_to.read_text(encoding="utf-8"))
        else:
            previous_snapshot = resolve_previous_snapshot(
                report_root=report_dir,
                current_report_dir=report_dir,
                scan_root=args.root,
            )
            if previous_snapshot is not None:
                previous_source = "auto:latest-in-report-dir"

        diff = None
        if previous_snapshot is not None:
            diff = diff_space_snapshots(snapshot, previous_snapshot)

        timeline_payload = None
        if args.watchdog_interval is not None or args.watchdog_duration is not None:
            timeline_payload = service.run_free_space_watchdog(
                root=args.root,
                report_dir=report_dir,
                interval_seconds=args.watchdog_interval if args.watchdog_interval is not None else 1.0,
                duration_seconds=args.watchdog_duration,
                max_rows=None,
                spike_threshold_bytes=None,
                cancel_flag=None,
            )

        artifacts = write_space_reports(
            report_dir=report_dir,
            snapshot=snapshot,
            top_dirs=top_dirs,
            by_ext=by_ext,
            diff=diff,
        )
        summary = {
            "command": "space-audit",
            "mode": "read_only",
            "safety": {
                "destructive_actions_performed": False,
                "safe_default": True,
                "note": "This command only reads filesystem metadata, writes reports, and performs no delete/move/prune operations.",
            },
            "input": {
                "root": str(args.root),
                "depth": max(0, int(args.depth)),
                "top_n": top_n,
                "compare_to": previous_source,
                "watchdog_interval": args.watchdog_interval,
                "watchdog_duration": args.watchdog_duration,
                "output_json": bool(args.as_json),
                "report_dir": str(report_dir),
            },
            "totals": snapshot.get("totals", {}),
            "compare": {
                "enabled": diff is not None,
                "summary": (diff or {}).get("summary"),
            },
            "artifacts": artifacts,
            "watchdog": timeline_payload,
        }
        _emit(summary, args.as_json)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
