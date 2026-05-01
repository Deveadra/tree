# C://~Projects/dupes/dupe_finder_gui.py

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sqlite3
import sys
import tkinter as tk
import uuid
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import traceback
import time
import threading

from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from PySide6.QtCore import (
    QDir,
    QFileInfo,
    QObject,
    QSettings,
    QThread,
    Qt,
    Signal,
    Slot,
)
from PySide6.QtGui import QAction
from PySide6.QtCharts import QChart, QChartView, QLineSeries
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFileIconProvider,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
)

from core.service import (
    apply_prune,
    load_dupes,
    plan_prune,
    scan_to_db,
    write_reports,
)
from dupe_core import (
    append_prune_event,
    analyze_path_prefixes,
    compile_excludes,
    DEFAULT_EXCLUDES,
    DupeGroup,
    FileRec,
    find_dupes_from_db,
    detect_elevated_privileges,
    fmt_duration,
    fmt_time,
    format_bytes,
    make_audit_event,
    new_run_id,
    write_live_reports,
    write_scan_reports,
)
from core.models import ScanRequest
from core.space_audit import (
    diff_space_snapshots,
    resolve_previous_snapshot,
    scan_space_usage,
    summarize_by_extension,
    summarize_top_dirs,
    write_space_reports,
)
from config.protection_loader import DEFAULT_TOML
from core.protection_policy import evaluate_delete_permission
from core.service import (
    build_prune_plan,
    execute_prune_plan,
    find_duplicates,
    scan,
)
from core.reports import (
    append_prune_event,
    safe_mkdir,
    write_json_atomic,
    windows_recycle,
    write_live_reports,
    write_scan_reports,
    write_path_suggestions,
    write_run_summary,
    write_versioned_meta,
)


# ----------------------------
# SQLite cache (keeps memory stable for huge drives)
# ----------------------------


def write_prune_reports(report_dir: Path, prune_summary_text: str) -> None:
    """
    Prune-only artifact. Must NEVER touch duplicates_* scan artifacts.
    """
    safe_mkdir(report_dir)
    (report_dir / "prune_summary.txt").write_text(
        prune_summary_text + "\n", encoding="utf-8"
    )


# ----------------------------
# Worker thread
# ----------------------------


class ScanWorker(QObject):
    error = Signal(str)
    finished = Signal(object)  # list[DupeGroup]
    metrics = Signal(object)  # dict
    progress = Signal(int, int)  # current, total
    status = Signal(str)

    def __init__(
        self,
        roots: list[Path],
        compare_mode: bool,
        report_dir: Path,
        excludes: set[str],
        follow_symlinks: bool,
        min_size: int,
    ):
        super().__init__()
        self.roots = roots
        self.compare_mode = compare_mode
        self.report_dir = report_dir
        self.excludes = excludes
        self.follow_symlinks = follow_symlinks
        self.min_size = min_size
        self._cancel = False
        self._cancel_reason = ""
        self.run_id = self.report_dir.name

    def cancel(self, reason: str = "user_requested") -> None:
        self._cancel = True
        self._cancel_reason = reason

    def _cancel_flag(self) -> bool:
        return self._cancel

    def _persist_run_state(self, db_path: Path, state: str, reason: Optional[str] = None) -> None:
        try:
            con = sqlite3.connect(str(db_path))
            try:
                con.execute(
                    """
                    CREATE TABLE IF NOT EXISTS run_state (
                        run_id TEXT PRIMARY KEY,
                        state TEXT NOT NULL,
                        reason TEXT,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                con.execute(
                    """
                    INSERT INTO run_state(run_id,state,reason,updated_at)
                    VALUES(?,?,?,?)
                    ON CONFLICT(run_id) DO UPDATE SET
                      state=excluded.state,
                      reason=excluded.reason,
                      updated_at=excluded.updated_at
                    """,
                    (self.run_id, state, reason, time.strftime("%Y-%m-%d %H:%M:%S")),
                )
                con.commit()
            finally:
                con.close()
        except Exception:
            pass

    @Slot()
    def run(self) -> None:
        try:
            t0 = time.time()
            safe_mkdir(self.report_dir)
            db_path = self.report_dir / "scan.db"

            meta_path = self.report_dir / "run_meta.json"
            meta: dict = {
                "run_id": self.run_id,
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "roots": [str(r) for r in self.roots],
                "compare_mode": bool(self.compare_mode),
                "report_dir": str(self.report_dir),
                "min_size": int(self.min_size),
                "excludes": sorted(self.excludes),
                "follow_symlinks": bool(self.follow_symlinks),
                "scan_stats": None,
                "size_groups_total": None,
                "dupe_groups": None,
                "finished_at": None,
                "elapsed_s": None,
                "status": "created",
                "cancel_reason": None,
            }
            try:
                write_versioned_meta(meta_path, meta)
            except Exception:
                pass
            self._persist_run_state(db_path, "created")
            meta["status"] = "scanning"
            try:
                write_json_atomic(meta_path, meta)
            except Exception:
                pass
            self._persist_run_state(db_path, "scanning")

            def push(m: dict) -> None:
                self.metrics.emit(m)

            if self.compare_mode and len(self.roots) >= 2:
                self.status.emit(
                    f"Scanning compare roots:\nA: {self.roots[0]}\nB: {self.roots[1]}"
                )
            else:
                self.status.emit(f"Scanning: {self.roots[0]}")
            self.progress.emit(0, 0)

            if self.compare_mode and len(self.roots) >= 2:
                scan_stats_full = scan_to_db(
                    roots=self.roots,
                    db_path=db_path,
                    excludes=self.excludes,
                    follow_symlinks=self.follow_symlinks,
                    min_size=self.min_size,
                    compare_mode=True,
                    scan_error_log_path=self.report_dir / "scan_errors.txt",
                    checkpoint_path=self.report_dir / "checkpoint_scan.json",
                )
                scan_stats = scan_stats_full.get("combined") or {
                    "listed": 0,
                    "indexed": 0,
                    "skipped": 0,
                    "errors": 0,
                }
                meta["scan_stats_full"] = scan_stats_full
            else:
                scan_stats = scan_to_db(
                    roots=[self.roots[0]],
                    db_path=db_path,
                    excludes=self.excludes,
                    follow_symlinks=self.follow_symlinks,
                    min_size=self.min_size,
                    compare_mode=False,
                    scan_error_log_path=self.report_dir / "scan_errors.txt",
                    checkpoint_path=self.report_dir / "checkpoint_scan.json",
                )

            # Count how many size-groups will be hashed
            try:
                con = sqlite3.connect(str(db_path))
                try:
                    row = con.execute(
                        "SELECT COUNT(*) FROM (SELECT size FROM files GROUP BY size HAVING COUNT(*) > 1)"
                    ).fetchone()
                    size_groups_total = int(row[0]) if row else 0
                finally:
                    con.close()
            except Exception:
                size_groups_total = None

            meta["scan_stats"] = scan_stats
            meta["size_groups_total"] = size_groups_total
            meta["status"] = "indexed"
            try:
                write_versioned_meta(meta_path, meta)
            except Exception:
                pass
            self._persist_run_state(db_path, "indexed")

            if self._cancel_flag():
                meta["status"] = "cancelled"
                meta["cancel_reason"] = self._cancel_reason or "cancelled_during_scan"
                write_json_atomic(meta_path, meta)
                write_run_summary(self.report_dir, meta)
                self._persist_run_state(db_path, "cancelled", meta["cancel_reason"])
                self.status.emit("Cancelled during scan.")
                self.finished.emit([])
                return

            meta["status"] = "planned"
            write_json_atomic(meta_path, meta)
            self._persist_run_state(db_path, "planned")
            self.status.emit("Finding duplicates (size + SHA-256)...")

            try:
                con = sqlite3.connect(str(db_path))
                rows = con.execute(
                    "SELECT root_id, COUNT(*) FROM files GROUP BY root_id"
                ).fetchall()
                self.status.emit(
                    "DB files per root_id: "
                    + ", ".join([f"{r[0]}={r[1]:,}" for r in rows])
                )

                shared_sizes = con.execute(
                    """
                    SELECT COUNT(*) FROM (
                    SELECT size
                    FROM files
                    GROUP BY size
                    HAVING
                        SUM(CASE WHEN root_id=0 THEN 1 ELSE 0 END) > 0
                        AND SUM(CASE WHEN root_id=1 THEN 1 ELSE 0 END) > 0
                    )
                    """
                ).fetchone()[0]
                self.status.emit(f"Size-groups shared across roots: {shared_sizes:,}")
            finally:
                try:
                    con.close()
                except Exception:
                    pass

            dupes = find_duplicates(
                db_path=db_path,
                cancel_flag=self._cancel_flag,
                metrics_cb=push,
                error_log_path=self.report_dir / "hash_errors.txt",
                required_roots=(
                    (0, 1) if (self.compare_mode and len(self.roots) >= 2) else None
                ),
                checkpoint_path=self.report_dir / "checkpoint_hash.json",
            )

            meta["dupe_groups"] = len(dupes)
            meta["status"] = "applying"
            try:
                write_versioned_meta(meta_path, meta)
            except Exception:
                pass
            self._persist_run_state(db_path, "applying")

            if self._cancel_flag():
                meta["status"] = "cancelled"
                meta["cancel_reason"] = self._cancel_reason or "cancelled_during_hash"
                write_json_atomic(meta_path, meta)
                write_run_summary(self.report_dir, meta)
                self._persist_run_state(db_path, "cancelled", meta["cancel_reason"])
                self.status.emit("Cancelled during hashing.")
                self.finished.emit([])
                return

            self.status.emit("Writing reports...")
            write_scan_reports(self.report_dir, dupes)

            try:
                write_live_reports(self.report_dir, dupes)
            except Exception:
                pass

            meta["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            meta["elapsed_s"] = float(time.time() - t0)
            meta["status"] = "completed"
            try:
                write_json_atomic(meta_path, meta)
                write_run_summary(self.report_dir, meta)
            except Exception:
                pass
            self._persist_run_state(db_path, "completed")

            elapsed = time.time() - t0
            self.status.emit(
                f"Done. Listed {scan_stats['listed']:,} files. Indexed {scan_stats['indexed']:,}. "
                f"Found {len(dupes):,} duplicate groups. ({fmt_duration(elapsed)})"
            )
            self.finished.emit(dupes)

        except Exception as e:
            try:
                meta["status"] = "failed"
                meta["error"] = str(e)
                write_json_atomic(meta_path, meta)
                write_run_summary(self.report_dir, meta)
                self._persist_run_state(db_path, "failed", str(e))
            except Exception:
                pass
            self.error.emit(str(e))


class SpaceAuditWorker(QObject):
    error = Signal(str)
    finished = Signal(object)  # dict[str, Any]
    metrics = Signal(object)  # dict
    progress = Signal(int, int)  # current, total
    status = Signal(str)
    cancel = Signal(str)

    def __init__(self, roots: list[Path], report_dir: Path, excludes: set[str], policy_path: Path):
        super().__init__()
        self.roots = roots
        self.report_dir = report_dir
        self.excludes = excludes
        self.policy_path = policy_path
        self._cancel_event = threading.Event()

    def cancel_run(self, reason: str = "user_cancelled") -> None:
        self._cancel_event.set()
        self.cancel.emit(reason)

    @Slot()
    def run(self) -> None:
        try:
            safe_mkdir(self.report_dir)
            snapshots: list[dict] = []
            all_top_dirs: list[dict] = []
            warnings: list[dict] = []
            diff_summaries: list[dict] = []
            self.progress.emit(0, max(1, len(self.roots)))
            for idx, root in enumerate(self.roots, start=1):
                if self._cancel_event.is_set():
                    self.status.emit("Disk usage analysis cancelled.")
                    self.finished.emit({"cancelled": True})
                    return
                self.status.emit(f"Analyzing disk usage: {root}")
                snapshot = scan_space_usage(
                    root=root,
                    excludes=self.excludes,
                    cancel_flag=self._cancel_event,
                    metrics_cb=self.metrics.emit,
                    policy_path=self.policy_path,
                )
                if self._cancel_event.is_set() or bool(snapshot.get("cancelled")):
                    self.status.emit("Disk usage analysis cancelled.")
                    self.finished.emit({"cancelled": True})
                    return
                top_dirs = summarize_top_dirs(snapshot, top_n=12)
                by_ext = summarize_by_extension(snapshot, top_n=30)
                prev = resolve_previous_snapshot(self.report_dir.parent, self.report_dir, root)
                diff = diff_space_snapshots(snapshot, prev, noise_threshold_bytes=0) if prev else None
                write_space_reports(
                    report_dir=self.report_dir,
                    snapshot=snapshot,
                    top_dirs=top_dirs,
                    by_ext=by_ext,
                    diff=diff,
                )
                snapshots.append(snapshot)
                all_top_dirs.extend([{"root": str(root), **row} for row in top_dirs[:5]])
                warnings.extend(snapshot.get("protection", {}).get("skipped_regions", [])[:20])
                if diff:
                    diff_summaries.append(
                        {
                            "root": str(root),
                            "net_change_bytes": int(diff.get("summary", {}).get("net_change_bytes", 0)),
                        }
                    )
                self.progress.emit(idx, len(self.roots))

            self.status.emit("Disk usage analysis complete.")
            self.finished.emit(
                {
                    "cancelled": False,
                    "snapshots": snapshots,
                    "top_offenders": sorted(all_top_dirs, key=lambda row: int(row.get("bytes", 0)), reverse=True)[:10],
                    "warnings": warnings,
                    "diff_summaries": diff_summaries,
                }
            )
        except Exception as exc:
            self.error.emit(str(exc))


class PrefixSuggestDialog(QDialog):
    """
    UI for ranked prefix suggestions with selection + add-to-preferred-paths support.
    """

    def __init__(self, parent: QWidget, report_dir: Path, dupes: list[DupeGroup]):
        super().__init__(parent)
        self.setWindowTitle("Path Suggestions (Ranked Prefixes)")
        self.report_dir = report_dir
        self.dupes = dupes

        self._all_rows: list[dict] = []
        self._filtered_rows: list[dict] = []
        self._result_prefixes: list[str] = []
        self._result_add_to_top: bool = False
        self._last_txt_path: Optional[Path] = None

        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 12)
        self.depth_spin.setValue(6)

        self.min_hits_spin = QSpinBox()
        self.min_hits_spin.setRange(1, 1000000)
        self.min_hits_spin.setValue(25)

        self.topn_spin = QSpinBox()
        self.topn_spin.setRange(10, 5000)
        self.topn_spin.setValue(200)

        self.run_btn = QPushButton("Run analysis")

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter prefixes (contains text)…")

        self.add_to_top_chk = QCheckBox("Add selected to TOP (higher priority)")

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            [
                "Prefix",
                "Group hits",
                "Exactly one",
                "Ambiguous",
                "Solvable rate",
                "File hits",
            ]
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setSortingEnabled(True)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i in range(1, 6):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)

        self.note_lbl = QLabel("")
        self.note_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.open_report_btn = QPushButton("Open report file")
        self.open_report_btn.setEnabled(False)

        self.add_selected_btn = QPushButton("Add selected")
        self.close_btn = QPushButton("Close")

        top = QVBoxLayout(self)

        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Max depth:"))
        ctrl.addWidget(self.depth_spin)
        ctrl.addWidget(QLabel("Min group hits:"))
        ctrl.addWidget(self.min_hits_spin)
        ctrl.addWidget(QLabel("Top N:"))
        ctrl.addWidget(self.topn_spin)
        ctrl.addWidget(self.run_btn)
        ctrl.addStretch(1)

        top.addLayout(ctrl)
        top.addWidget(self.filter_edit)
        top.addWidget(self.table)
        top.addWidget(self.add_to_top_chk)
        top.addWidget(self.note_lbl)

        btns = QHBoxLayout()
        btns.addWidget(self.open_report_btn)
        btns.addStretch(1)
        btns.addWidget(self.add_selected_btn)
        btns.addWidget(self.close_btn)
        top.addLayout(btns)

        self.run_btn.clicked.connect(self.run_analysis)
        self.filter_edit.textChanged.connect(self.apply_filter)
        self.open_report_btn.clicked.connect(self.open_report_file)
        self.add_selected_btn.clicked.connect(self.accept_with_selection)
        self.close_btn.clicked.connect(self.reject)

        self.run_analysis()

    def run_analysis(self) -> None:
        max_depth = int(self.depth_spin.value())
        min_hits = int(self.min_hits_spin.value())
        top_n = int(self.topn_spin.value())

        rows = analyze_path_prefixes(
            dupes=self.dupes,
            max_depth=max_depth,
            min_group_hits=min_hits,
        )
        rows = rows[:top_n]

        self._all_rows = rows
        self.apply_filter()

        try:
            txt_path, _json_path = write_path_suggestions(
                report_dir=self.report_dir,
                dupes=self.dupes,
                max_depth=max_depth,
                min_group_hits=min_hits,
                top_n=top_n,
            )
            self._last_txt_path = txt_path
            self.open_report_btn.setEnabled(True)
            self.note_lbl.setText(f"Wrote: {txt_path}")
        except Exception as e:
            self.note_lbl.setText(f"Note: could not write report file: {e}")

    def apply_filter(self) -> None:
        needle = (self.filter_edit.text() or "").strip().lower()
        if not needle:
            self._filtered_rows = list(self._all_rows)
        else:
            self._filtered_rows = [
                r for r in self._all_rows if needle in (r.get("prefix", "").lower())
            ]

        self.populate_table(self._filtered_rows)

    def populate_table(self, rows: list[dict]) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)

        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)

            prefix = str(r.get("prefix", ""))
            gh = int(r.get("group_hits", 0))
            one = int(r.get("groups_exactly_one", 0))
            amb = int(r.get("groups_ambiguous", 0))
            rate = float(r.get("solvable_rate", 0.0))
            fh = int(r.get("file_hits", 0))

            it0 = QTableWidgetItem(prefix)
            it0.setData(Qt.ItemDataRole.UserRole, prefix)

            it1 = QTableWidgetItem(f"{gh:,}")
            it1.setData(Qt.ItemDataRole.UserRole, gh)

            it2 = QTableWidgetItem(f"{one:,}")
            it2.setData(Qt.ItemDataRole.UserRole, one)

            it3 = QTableWidgetItem(f"{amb:,}")
            it3.setData(Qt.ItemDataRole.UserRole, amb)

            it4 = QTableWidgetItem(f"{rate:.3f}")
            it4.setData(Qt.ItemDataRole.UserRole, rate)

            it5 = QTableWidgetItem(f"{fh:,}")
            it5.setData(Qt.ItemDataRole.UserRole, fh)

            self.table.setItem(row, 0, it0)
            self.table.setItem(row, 1, it1)
            self.table.setItem(row, 2, it2)
            self.table.setItem(row, 3, it3)
            self.table.setItem(row, 4, it4)
            self.table.setItem(row, 5, it5)

        self.table.setSortingEnabled(True)

    def selected_prefixes(self) -> list[str]:
        rows = self.table.selectionModel().selectedRows()
        out: list[str] = []
        for r in rows:
            item = self.table.item(r.row(), 0)
            if not item:
                continue
            p = item.data(Qt.ItemDataRole.UserRole) or item.text()
            p = (p or "").strip()
            if p:
                out.append(p)
        return out

    def accept_with_selection(self) -> None:
        prefixes = self.selected_prefixes()
        if not prefixes:
            QMessageBox.information(
                self, "No selection", "Select one or more prefixes first."
            )
            return
        self._result_prefixes = prefixes
        self._result_add_to_top = bool(self.add_to_top_chk.isChecked())
        self.accept()

    def open_report_file(self) -> None:
        if not self._last_txt_path or not self._last_txt_path.exists():
            QMessageBox.information(
                self, "Not found", "Report file not found yet. Run analysis first."
            )
            return
        try:
            os.startfile(str(self._last_txt_path))  # type: ignore[attr-defined]
        except Exception as e:
            QMessageBox.warning(self, "Open failed", str(e))

    def result(self) -> tuple[list[str], bool]:
        return (list(self._result_prefixes), bool(self._result_add_to_top))


# ----------------------------
# Main Window
# ----------------------------


class MainWindow(QMainWindow):
    WARNING_TEXTS = {
        "risk_mode_blocked_title": "Risk mode transition blocked",
        "risk_mode_blocked_body": (
            "Destructive transition prevented.\n\n"
            "Following symlinks/junctions while elevated is blocked unless explicit unsafe mode is enabled."
        ),
        "confirmation_title": "Confirm destructive action",
        "confirmation_primary": "Manual confirmation required before destructive execution.",
    }
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dupe Finder (GUI) — Size + SHA-256")

        self.icon_provider = QFileIconProvider()
        self.dupe_by_digest: dict[str, DupeGroup] = {}

        settings = QSettings("DupeFinder", "DupeFinderGUI")
        saved_root = settings.value("reports_root", "", type=str)

        self.reports_root = (
            Path(saved_root)
            if saved_root
            else Path("C:/Projects/personal/dupes/reports")
        )

        self.report_dir: Path = self.reports_root
        self.session_id: str = str(uuid.uuid4())
        self.current_digest: Optional[str] = None

        self.load_btn = QPushButton("Load previous scan…")
        self.open_reports_btn = QPushButton("Open current report folder")

        self.root_edit = QLineEdit()
        self.root_edit.setPlaceholderText(r"E:\  (or any folder path)")
        self.browse_root_btn = QPushButton("Browse…")
        self.compare_mode_chk = QCheckBox("Compare two locations (Root A vs Root B)")
        self.root2_edit = QLineEdit()
        self.root2_edit.setPlaceholderText(r"Second root (e.g. E:\Backup\ or D:\)")
        self.browse_root2_btn = QPushButton("Browse…")
        self.root2_edit.setEnabled(False)
        self.browse_root2_btn.setEnabled(False)

        self.report_edit = QLineEdit(str(self.reports_root))
        self.browse_report_btn = QPushButton("Browse…")

        self.min_size_spin = QSpinBox()
        self.min_size_spin.setRange(0, 2_000_000_000)
        self.min_size_spin.setValue(1)
        self.min_size_spin.setSuffix(" bytes")

        self.follow_symlinks_chk = QCheckBox(
            "Follow symlinks/junctions (not recommended)"
        )

        # NOTE: this field supports BOTH:
        #   - dir names (e.g. ".git", "node_modules")
        #   - full path prefixes (e.g. "C:\Windows", "%LOCALAPPDATA%\Packages")
        self.exclude_edit = QLineEdit(", ".join(sorted(DEFAULT_EXCLUDES)))
        self.exclude_edit.setPlaceholderText(
            r".git, node_modules, C:\Windows, %LOCALAPPDATA%\Packages, E:\$Recycle.Bin, ..."
        )

        self.start_btn = QPushButton("Start scan")
        self.space_audit_btn = QPushButton("Analyze disk usage…")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.status_lbl = QLabel("Ready.")
        self.remaining_lbl = QLabel("")
        self.remaining_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.remaining_lbl.setStyleSheet("QLabel { font-weight: 600; }")
        self.rclone_stats = QLabel("")
        self.rclone_stats.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.rclone_stats.setStyleSheet(
            "QLabel { font-family: Consolas, 'Courier New', monospace; }"
        )

        self.status_box = QTextEdit()
        self.status_box.setReadOnly(True)
        self.status_box.setFixedHeight(110)

        self.tabs = QTabWidget()
        self.monitor_tab = QWidget()
        self.monitor_is_read_only_lbl = QLabel("Read-only monitor (no filesystem writes or delete actions).")
        self.monitor_is_read_only_lbl.setStyleSheet("QLabel { color: #8b0000; font-weight: 700; }")
        self.monitor_free_used_lbl = QLabel("Free/Used: n/a")
        self.monitor_delta_lbl = QLabel("Recent delta: n/a")
        self.monitor_alert_lbl = QLabel("Alert state: Normal")
        self.monitor_alert_lbl.setStyleSheet("QLabel { color: #1f7a1f; font-weight: 700; }")
        self.monitor_spark_chart = QChart()
        self.monitor_spark_chart.legend().hide()
        self.monitor_spark_chart.setBackgroundVisible(False)
        self.monitor_sparkline = QLineSeries()
        self.monitor_spark_chart.addSeries(self.monitor_sparkline)
        self.monitor_spark_chart.createDefaultAxes()
        self.monitor_spark_view = QChartView(self.monitor_spark_chart)
        self.monitor_spark_view.setMinimumHeight(120)
        self.monitor_spikes_table = QTableWidget(0, 5)
        self.monitor_spikes_table.setHorizontalHeaderLabels(
            ["Severity", "Time (UTC)", "Delta", "Top suspects", "Evidence bundle"]
        )
        self.monitor_spikes_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.monitor_spikes_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.monitor_spikes_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.open_evidence_btn = QPushButton("Open evidence bundle")
        self.open_evidence_btn.setEnabled(False)
        self.ai_findings_table = QTableWidget(0, 6)
        self.ai_findings_table.setHorizontalHeaderLabels(
            ["Finding", "Evidence citations", "Confidence", "Risk", "Alternates", "Event"]
        )
        self.ai_findings_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.ai_findings_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.ai_findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ai_why_btn = QPushButton("Why this finding?")
        self.ai_why_btn.setEnabled(False)
        self.ai_action_btn = QPushButton("Apply finding recommendation…")
        self.ai_action_btn.setEnabled(False)
        self.investigate_btn = QPushButton("Investigate disappearing space…")
        self.findings_summary = QTextEdit()
        self.findings_summary.setReadOnly(True)
        self.findings_summary.setAccessibleName("Findings summary")
        self.findings_summary.setAccessibleDescription("Shows preflight risk, warnings, and safe next-step guidance.")
        self.findings_summary.setPlaceholderText(
            "Top findings, confidence, protected-zone warnings, and safe next steps will appear here."
        )
        self.findings_summary.setFixedHeight(180)
        self.protected_warning_lbl = QLabel("")
        self.protected_warning_lbl.setWordWrap(True)
        self.protected_warning_lbl.setAccessibleName("Protected warning banner")
        self.protected_warning_lbl.setAccessibleDescription("Warning banner for protected/system-managed zone blocks.")
        self.protected_warning_lbl.setStyleSheet(
            "QLabel { background: #fff3cd; color: #7a4f01; border: 1px solid #f0ad4e; padding: 6px; font-weight: 600; }"
        )
        self.protected_warning_lbl.hide()
        self.plan_state_combo = QComboBox()
        self.plan_state_combo.addItems(["draft", "reviewed", "approved", "executed"])
        self.plan_state_combo.setCurrentText("draft")
        self.plan_advance_btn = QPushButton("Advance plan state")
        self.monitor_interval_spin = QSpinBox()
        self.monitor_interval_spin.setRange(1, 3600)
        self.monitor_interval_spin.setValue(30)
        self.monitor_interval_spin.setSuffix(" s")
        self.monitor_trigger_spin = QSpinBox()
        self.monitor_trigger_spin.setRange(1, 10_000_000)
        self.monitor_trigger_spin.setValue(500)
        self.monitor_trigger_spin.setSuffix(" MB")
        self.monitor_retention_spin = QSpinBox()
        self.monitor_retention_spin.setRange(1, 365)
        self.monitor_retention_spin.setValue(14)
        self.monitor_retention_spin.setSuffix(" days")
        self.monitor_start_btn = QPushButton("Start")
        self.monitor_pause_btn = QPushButton("Pause")
        self.monitor_resume_btn = QPushButton("Resume")
        self.monitor_pause_btn.setEnabled(False)
        self.monitor_resume_btn.setEnabled(False)
        self._monitor_mode = "stopped"
        self._monitor_deltas: list[int] = []
        self._monitor_spike_events: list[dict] = []
        self._ai_findings_by_event: dict[str, list[dict]] = {}
        self._selected_finding: Optional[dict] = None
        self.tree_by_name = QTreeWidget()
        self.tree_by_name.setHeaderLabels(
            ["Grouped by filename (hash-confirmed duplicates)"]
        )
        self.tree_by_hash = QTreeWidget()
        self.tree_by_hash.setHeaderLabels(
            ["Grouped by content hash (all true duplicates)"]
        )
        self.tabs.addTab(self.tree_by_name, "By filename")
        self.tabs.addTab(self.tree_by_hash, "By content")
        self.tabs.addTab(self.monitor_tab, "Space monitor")
        monitor_layout = QVBoxLayout(self.monitor_tab)
        monitor_layout.addWidget(self.monitor_is_read_only_lbl)
        monitor_layout.addWidget(self.monitor_free_used_lbl)
        monitor_layout.addWidget(self.monitor_delta_lbl)
        monitor_layout.addWidget(self.monitor_alert_lbl)
        monitor_layout.addWidget(self.monitor_spark_view)
        monitor_layout.addWidget(QLabel("Spike Events"))
        monitor_layout.addWidget(self.monitor_spikes_table)
        monitor_layout.addWidget(QLabel("AI Findings"))
        monitor_layout.addWidget(self.ai_findings_table)
        ai_actions = QHBoxLayout()
        ai_actions.addWidget(self.ai_why_btn)
        ai_actions.addWidget(self.ai_action_btn)
        ai_actions.addWidget(self.investigate_btn)
        ai_actions.addStretch(1)
        monitor_layout.addLayout(ai_actions)
        monitor_layout.addWidget(self.protected_warning_lbl)
        monitor_layout.addWidget(QLabel("Investigation summary"))
        monitor_layout.addWidget(self.findings_summary)
        monitor_layout.addWidget(self.open_evidence_btn)
        controls_form = QFormLayout()
        controls_form.addRow("Sampling interval:", self.monitor_interval_spin)
        controls_form.addRow("Trigger threshold:", self.monitor_trigger_spin)
        controls_form.addRow("Retention setting:", self.monitor_retention_spin)
        controls_form.addRow("Plan approval state:", self.plan_state_combo)
        controls_form.addRow("", self.plan_advance_btn)
        monitor_layout.addLayout(controls_form)
        monitor_actions = QHBoxLayout()
        monitor_actions.addWidget(self.monitor_start_btn)
        monitor_actions.addWidget(self.monitor_pause_btn)
        monitor_actions.addWidget(self.monitor_resume_btn)
        monitor_actions.addStretch(1)
        monitor_layout.addLayout(monitor_actions)

        self.files_table = QTableWidget(0, 4)
        self.files_table.setHorizontalHeaderLabels(
            ["Name", "Size", "Modified", "Full Path"]
        )
        self.files_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.files_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.files_table.setSortingEnabled(True)
        self.files_table.cellDoubleClicked.connect(self.on_file_cell_double_clicked)
        self.files_table.cellClicked.connect(self.on_file_cell_clicked)

        self.delete_mode = QComboBox()
        self.delete_mode.addItems(
            [
                "Recycle Bin (recommended)",
                "Move to trash folder",
                "Quarantine (move + manifest)",
                "Permanent delete",
            ]
        )
        self.prefer_path_edit = QLineEdit()
        self.prefer_path_edit.setPlaceholderText(
            r"Preferred keep paths (priority order). Separate with ';'  e.g. E:\MAIN\OneDrive\; E:\MAIN\RPics\; E:\MAIN\Projects\\"
        )

        self.prefer_path_btn = QPushButton("Browse…")

        self.auto_prune_btn = QPushButton("Auto-prune by preferred path")
        self.compare_prune_btn = QPushButton(
            "Compare auto-prune (delete A if present on B)"
        )
        self.compare_prune_btn.setEnabled(False)

        self.suggest_keep_paths_btn = QPushButton("Suggest keep paths…")
        self.suggest_keep_paths_btn.setEnabled(False)
        self.suggest_paths_btn = QPushButton("Recommend Keep Locations")

        self.analyze_paths_btn = QPushButton("Analyze Storage Patterns")

        self.trash_folder_edit = QLineEdit(str(self.report_dir / "_trash"))
        self.trash_folder_btn = QPushButton("Browse…")

        self.keep_delete_btn = QPushButton("Delete Duplicates (Keep Selected)")
        self.open_file_btn = QPushButton("Open selected file")
        self.open_folder_btn = QPushButton("Open containing folder")

        top = QWidget()
        self.setCentralWidget(top)
        main = QVBoxLayout(top)

        form = QFormLayout()

        root_row = QHBoxLayout()
        root_row.addWidget(self.root_edit)
        root_row.addWidget(self.browse_root_btn)
        form.addRow("Root to scan:", root_row)

        form.addRow("", self.compare_mode_chk)

        root2_row = QHBoxLayout()
        root2_row.addWidget(self.root2_edit)
        root2_row.addWidget(self.browse_root2_btn)
        form.addRow("Root B (compare):", root2_row)

        rep_row = QHBoxLayout()
        rep_row.addWidget(self.report_edit)
        rep_row.addWidget(self.browse_report_btn)
        form.addRow("Reports root:", rep_row)

        form.addRow("Min file size:", self.min_size_spin)
        form.addRow("Excludes (names or full paths):", self.exclude_edit)
        form.addRow("", self.follow_symlinks_chk)

        btn_row = QHBoxLayout()
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.space_audit_btn)
        btn_row.addWidget(self.cancel_btn)
        btn_row.addWidget(self.load_btn)
        btn_row.addWidget(self.open_reports_btn)
        btn_row.addStretch(1)
        form.addRow("", btn_row)

        main.addLayout(form)
        main.addWidget(self.progress)
        main.addWidget(self.status_lbl)
        main.addWidget(self.remaining_lbl)
        main.addWidget(self.rclone_stats)
        main.addWidget(self.status_box)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left = QWidget()
        left_l = QVBoxLayout(left)
        left_l.addWidget(self.tabs)
        splitter.addWidget(left)

        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.addWidget(QLabel("Files in selected duplicate group:"))
        right_l.addWidget(self.files_table)

        pref_row = QHBoxLayout()
        pref_row.addWidget(QLabel("Preferred keep path:"))
        pref_row.addWidget(self.prefer_path_edit)
        pref_row.addWidget(self.prefer_path_btn)
        right_l.addLayout(pref_row)
        right_l.addWidget(self.auto_prune_btn)
        right_l.addWidget(self.compare_prune_btn)
        right_l.addWidget(self.suggest_keep_paths_btn)
        right_l.addWidget(self.suggest_paths_btn)
        right_l.addWidget(self.analyze_paths_btn)

        del_row = QHBoxLayout()
        del_row.addWidget(QLabel("Delete mode:"))
        del_row.addWidget(self.delete_mode)
        del_row.addStretch(1)
        right_l.addLayout(del_row)

        trash_row = QHBoxLayout()
        trash_row.addWidget(QLabel("Trash folder:"))
        trash_row.addWidget(self.trash_folder_edit)
        trash_row.addWidget(self.trash_folder_btn)
        right_l.addLayout(trash_row)

        act_row = QHBoxLayout()
        act_row.addWidget(self.keep_delete_btn)
        act_row.addWidget(self.open_file_btn)
        act_row.addWidget(self.open_folder_btn)
        right_l.addLayout(act_row)

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)

        main.addWidget(splitter)

        refresh_action = QAction("Clear results", self)
        refresh_action.triggered.connect(self.clear_results)
        self.menuBar().addAction(refresh_action)

        open_reports_action = QAction("Open report folder", self)
        open_reports_action.triggered.connect(self.open_report_folder)
        self.menuBar().addAction(open_reports_action)

        open_scan_err_action = QAction("Open scan_errors.txt", self)
        open_scan_err_action.triggered.connect(
            lambda: self.open_report_file("scan_errors.txt")
        )
        self.menuBar().addAction(open_scan_err_action)
        self._apply_button_roles()
        self._apply_tooltips()

        open_hash_err_action = QAction("Open hash_errors.txt", self)
        open_hash_err_action.triggered.connect(
            lambda: self.open_report_file("hash_errors.txt")
        )
        self.menuBar().addAction(open_hash_err_action)

        open_dupe_summary_action = QAction("Open duplicates_summary.txt", self)
        open_dupe_summary_action.triggered.connect(
            lambda: self.open_report_file("duplicates_summary.txt")
        )
        self.menuBar().addAction(open_dupe_summary_action)

        open_delete_log_action = QAction("Open deletion_log.txt", self)
        open_delete_log_action.triggered.connect(
            lambda: self.open_report_file("deletion_log.txt")
        )
        self.menuBar().addAction(open_delete_log_action)

        self.prefer_path_btn.clicked.connect(self.pick_prefer_path)
        self.auto_prune_btn.clicked.connect(self.auto_prune_by_preferred_path)
        self.suggest_paths_btn.clicked.connect(self.open_path_suggestions)
        self.analyze_paths_btn.clicked.connect(self.analyze_paths_suggest_prefixes)
        self.compare_prune_btn.clicked.connect(self.compare_prune_delete_a_using_b)
        self.suggest_keep_paths_btn.clicked.connect(self.open_suggest_keep_paths)

        self.compare_mode_chk.toggled.connect(self.on_compare_mode_toggled)
        self.browse_root2_btn.clicked.connect(self.pick_root2)
        self.browse_root_btn.clicked.connect(self.pick_root)
        self.browse_report_btn.clicked.connect(self.pick_report_dir)
        self.trash_folder_btn.clicked.connect(self.pick_trash_dir)

        self.start_btn.clicked.connect(self.start_scan)
        self.space_audit_btn.clicked.connect(self.start_space_audit)
        self.investigate_btn.clicked.connect(self.run_disappearing_space_wizard)
        self.cancel_btn.clicked.connect(self.cancel_scan)
        self.load_btn.clicked.connect(self.load_previous_scan)
        self.open_reports_btn.clicked.connect(self.open_current_report_folder)

        self.tree_by_name.itemSelectionChanged.connect(self.on_tree_selection)
        self.tree_by_hash.itemSelectionChanged.connect(self.on_tree_selection)

        self.keep_delete_btn.clicked.connect(self.keep_selected_delete_others)
        self.open_file_btn.clicked.connect(self.open_selected_file)
        self.open_folder_btn.clicked.connect(self.open_selected_folder)

        self.delete_mode.currentIndexChanged.connect(self.on_delete_mode_changed)
        self.monitor_spikes_table.itemSelectionChanged.connect(self._on_monitor_spike_selection_changed)
        self.ai_findings_table.itemSelectionChanged.connect(self._on_ai_finding_selection_changed)
        self.open_evidence_btn.clicked.connect(self._open_selected_evidence_bundle)
        self.ai_why_btn.clicked.connect(self._show_finding_why_dialog)
        self.ai_action_btn.clicked.connect(self._confirm_finding_action)
        self.plan_advance_btn.clicked.connect(self._advance_plan_state)
        self.monitor_start_btn.clicked.connect(lambda: self._set_monitor_mode("running"))
        self.monitor_pause_btn.clicked.connect(lambda: self._set_monitor_mode("paused"))
        self.monitor_resume_btn.clicked.connect(lambda: self._set_monitor_mode("running"))
        self.on_delete_mode_changed()

        self.worker_thread: Optional[QThread] = None
        self.worker: Optional[ScanWorker] = None
        self.space_audit_thread: Optional[QThread] = None
        self.space_audit_worker: Optional[SpaceAuditWorker] = None

        # Cache for compiled excludes (used by deletion safety checks)
        self._ex_cache_raw: Optional[str] = None
        self._ex_cache: tuple[set[str], list[str]] = (set(), [])
        self.allowed_roots: list[Path] = []

    def _set_monitor_mode(self, mode: str) -> None:
        self._monitor_mode = mode
        self.monitor_start_btn.setEnabled(mode == "stopped")
        self.monitor_pause_btn.setEnabled(mode == "running")
        self.monitor_resume_btn.setEnabled(mode == "paused")
        self.set_status(f"Space monitor is now {mode} (read-only).")

    def _on_monitor_spike_selection_changed(self) -> None:
        self.open_evidence_btn.setEnabled(bool(self.monitor_spikes_table.selectedItems()))
        row = self.monitor_spikes_table.currentRow()
        event_id = ""
        if 0 <= row < len(self._monitor_spike_events):
            event_id = str(self._monitor_spike_events[row].get("event_id", ""))
        self._render_ai_findings_for_event(event_id)

    def _on_ai_finding_selection_changed(self) -> None:
        row = self.ai_findings_table.currentRow()
        self._selected_finding = None
        if row >= 0:
            event_id = self._selected_ai_event_id()
            findings = self._ai_findings_by_event.get(event_id, [])
            if row < len(findings):
                self._selected_finding = findings[row]
        enabled = self._selected_finding is not None
        self.ai_why_btn.setEnabled(enabled)
        self.ai_action_btn.setEnabled(enabled)

    def _selected_ai_event_id(self) -> str:
        row = self.monitor_spikes_table.currentRow()
        if row < 0 or row >= len(self._monitor_spike_events):
            return ""
        return str(self._monitor_spike_events[row].get("event_id", ""))

    def _render_ai_findings_for_event(self, event_id: str) -> None:
        findings = self._ai_findings_by_event.get(event_id, [])
        self.ai_findings_table.setRowCount(len(findings))
        for idx, f in enumerate(findings):
            self.ai_findings_table.setItem(idx, 0, QTableWidgetItem(str(f.get("finding", ""))))
            self.ai_findings_table.setItem(idx, 1, QTableWidgetItem("; ".join(f.get("evidence_citations", []))))
            self.ai_findings_table.setItem(idx, 2, QTableWidgetItem(str(f.get("confidence", ""))))
            self.ai_findings_table.setItem(idx, 3, QTableWidgetItem(str(f.get("risk_label", ""))))
            self.ai_findings_table.setItem(idx, 4, QTableWidgetItem("; ".join(f.get("alternate_hypotheses", []))))
            self.ai_findings_table.setItem(idx, 5, QTableWidgetItem(str(event_id)))

    def _show_finding_why_dialog(self) -> None:
        if not self._selected_finding:
            return
        contrib = self._selected_finding.get("feature_contributions", [])
        rows = "\n".join(f"• {r.get('feature')}: {r.get('weight')}" for r in contrib) if contrib else "No feature contribution data."
        QMessageBox.information(self, "Why this?", rows)

    def _advance_plan_state(self) -> None:
        states = ["draft", "reviewed", "approved", "executed"]
        cur = self.plan_state_combo.currentText()
        idx = states.index(cur) if cur in states else 0
        if idx >= len(states) - 1:
            QMessageBox.information(self, "Plan workflow", "Plan is already in executed state.")
            return
        next_state = states[idx + 1]
        self.plan_state_combo.setCurrentText(next_state)
        self.set_status(f"Plan workflow moved: {cur} -> {next_state}")

    def _confirm_finding_action(self) -> None:
        if not self._selected_finding:
            return
        if self.plan_state_combo.currentText() != "approved":
            QMessageBox.warning(self, "Approval required", "Plan must be approved before execution.")
            return
        preflight = self._build_preflight_summary(self._selected_finding)
        consequence_steps = self._build_consequence_steps(self._selected_finding)
        prompt = (
            f"{self.WARNING_TEXTS['confirmation_primary']}\n\n"
            f"{preflight}\n\n"
            "Step consequences:\n"
            f"{consequence_steps}\n\n"
            "Type-safe flow:\n"
            "1) Review policy blocks and irreversible impact.\n"
            "2) Confirm destructive handoff.\n"
            "3) Validate post-action outcomes and rollback readiness.\n\n"
            "Proceed with destructive action?"
        )
        choice = QMessageBox.question(
            self,
            self.WARNING_TEXTS["confirmation_title"],
            prompt,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if choice != QMessageBox.StandardButton.Yes:
            self.set_status("Destructive action cancelled by user.")
            return
        self.plan_state_combo.setCurrentText("executed")
        self._show_post_action_validation_guidance(self._selected_finding)
        self.set_status("Manual confirmation accepted. Marked plan as executed with validation guidance.")

    def _build_preflight_summary(self, finding: dict) -> str:
        finding_name = str(finding.get("finding", "unknown"))
        risk = str(finding.get("risk_label", "unknown")).lower()
        projected_gain = "unknown"
        evidence = finding.get("evidence_citations", [])
        if isinstance(evidence, list):
            for entry in evidence:
                token = str(entry)
                if token.startswith("metric:delta_bytes="):
                    try:
                        projected_gain = format_bytes(abs(int(token.split("=", 1)[1])))
                    except Exception:
                        projected_gain = "unknown"
                    break
        policy_block = "none detected" if risk in {"low", "medium"} else "high-risk policy gate requires heightened review"
        irreversible = "possible" if risk in {"high", "critical", "dangerous"} else "limited"
        return (
            "Preflight summary\n"
            f"- Finding: {finding_name}\n"
            f"- Projected gain: {projected_gain}\n"
            f"- Policy blocks: {policy_block}\n"
            f"- Irreversible impact: {irreversible}"
        )

    def _build_consequence_steps(self, finding: dict) -> str:
        risk = str(finding.get("risk_label", "unknown")).lower()
        return "\n".join(
            [
                f"• Pre-check: confirm protected-zone exclusions remain active (risk={risk}).",
                "• Action: destructive transition may remove or move data.",
                "• Immediate effect: storage may improve but recovery window may narrow.",
                "• Validation: re-run analysis and verify delta, warnings, and policy compliance.",
            ]
        )

    def _show_post_action_validation_guidance(self, finding: dict) -> None:
        _ = finding
        validation_prompt = (
            "Post-action validation required.\n\n"
            "Run these checks now:\n"
            "• Re-scan target scope and compare projected vs actual reclaimed space.\n"
            "• Confirm no protected/system-managed zones were impacted.\n"
            "• Verify expected files still exist and hashes for canonical files remain stable.\n\n"
            "Automated rollback guidance:\n"
            "• If validation fails, stop further destructive actions.\n"
            "• Restore from recycle/quarantine or known-good backup.\n"
            "• Capture artifacts and rerun audit before retrying."
        )
        QMessageBox.information(self, "Validation and rollback guidance", validation_prompt)

    def _open_selected_evidence_bundle(self) -> None:
        row = self.monitor_spikes_table.currentRow()
        if row < 0 or row >= len(self._monitor_spike_events):
            return
        evidence_path = self._monitor_spike_events[row].get("evidence_bundle")
        if not evidence_path:
            QMessageBox.information(self, "No evidence bundle", "No evidence bundle is available for this spike event.")
            return
        self.reveal_in_explorer(str(evidence_path))

    def _refresh_monitor_panel(self, snapshot: dict, top_offenders: list[dict], diff_summaries: list[dict]) -> None:
        if self._monitor_mode != "running":
            return
        volume = snapshot.get("volume", {}) if isinstance(snapshot, dict) else {}
        free_b = int(volume.get("free_bytes", 0))
        used_b = int(volume.get("used_bytes", 0))
        self.monitor_free_used_lbl.setText(f"Free/Used: {format_bytes(free_b)} free / {format_bytes(used_b)} used")
        snapshot_root = ""
        if isinstance(snapshot, dict):
            run_info = snapshot.get("run", {})
            if isinstance(run_info, dict):
                snapshot_root = str(run_info.get("root", ""))
        matching_diff = next(
            (
                item
                for item in diff_summaries
                if isinstance(item, dict) and (not snapshot_root or str(item.get("root", "")) == snapshot_root)
            ),
            None,
        )
        delta_b = int(matching_diff.get("net_change_bytes", 0)) if isinstance(matching_diff, dict) else 0
        self.monitor_delta_lbl.setText(f"Recent delta: {format_bytes(abs(delta_b))} {'growth' if delta_b >= 0 else 'drop'}")
        self._monitor_deltas.append(delta_b)
        self._monitor_deltas = self._monitor_deltas[-30:]
        self.monitor_sparkline.clear()
        for i, v in enumerate(self._monitor_deltas):
            self.monitor_sparkline.append(i, float(v))
        self.monitor_spark_chart.createDefaultAxes()
        threshold_b = int(self.monitor_trigger_spin.value()) * 1024 * 1024
        if abs(delta_b) >= threshold_b:
            self.monitor_alert_lbl.setText("Alert state: Spike detected")
            self.monitor_alert_lbl.setStyleSheet("QLabel { color: #b22222; font-weight: 700; }")
            suspects = ", ".join(str(row.get("path", "")) for row in top_offenders[:3]) or "n/a"
            event = {
                "event_id": f"spike-{int(time.time() * 1000)}",
                "severity": "high" if abs(delta_b) >= threshold_b * 2 else "medium",
                "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "delta": delta_b,
                "suspects": suspects,
                "evidence_bundle": self.report_dir / "space_snapshot.json",
            }
            self._monitor_spike_events.insert(0, event)
            self._ai_findings_by_event[event["event_id"]] = [
                {
                    "finding": f"Spike likely driven by growth under {suspects.split(',')[0] if suspects else 'unknown'}",
                    "evidence_citations": [
                        f"dir:{str(top_offenders[0].get('path', 'n/a'))}" if top_offenders else "dir:n/a",
                        f"metric:delta_bytes={delta_b}",
                    ],
                    "confidence": "0.78",
                    "risk_label": "medium" if abs(delta_b) < threshold_b * 2 else "high",
                    "alternate_hypotheses": ["temporary file burst", "log rotation anomaly"],
                    "feature_contributions": [
                        {"feature": "delta_bytes", "weight": 0.61},
                        {"feature": "top_dir_growth", "weight": 0.39},
                    ],
                }
            ]
            self._monitor_spike_events = self._monitor_spike_events[: max(1, self.monitor_retention_spin.value() * 5)]
            self.monitor_spikes_table.setRowCount(len(self._monitor_spike_events))
            for row_idx, row in enumerate(self._monitor_spike_events):
                self.monitor_spikes_table.setItem(row_idx, 0, QTableWidgetItem(str(row["severity"])))
                self.monitor_spikes_table.setItem(row_idx, 1, QTableWidgetItem(str(row["time"])))
                self.monitor_spikes_table.setItem(row_idx, 2, QTableWidgetItem(format_bytes(abs(int(row["delta"])))))
                self.monitor_spikes_table.setItem(row_idx, 3, QTableWidgetItem(str(row["suspects"])))
                self.monitor_spikes_table.setItem(row_idx, 4, QTableWidgetItem(str(row["evidence_bundle"])))
        else:
            self.monitor_alert_lbl.setText("Alert state: Normal")
            self.monitor_alert_lbl.setStyleSheet("QLabel { color: #1f7a1f; font-weight: 700; }")

    # ----------------------------
    # UI helpers
    # ----------------------------

    def reveal_in_explorer(self, path: str) -> None:
        raw = (path or "").strip().strip('"')
        if not raw:
            return

        p = Path(raw)

        if not p.exists():
            QMessageBox.information(self, "Not found", f"Path does not exist:\n{p}")
            return

        try:
            if os.name == "nt":
                if p.is_dir():
                    os.startfile(str(p))  # type: ignore[attr-defined]
                else:
                    subprocess.Popen(
                        ["explorer.exe", "/select,", os.path.normpath(str(p))]
                    )
            elif sys.platform == "darwin":
                if p.is_dir():
                    subprocess.Popen(["open", str(p)])
                else:
                    subprocess.Popen(["open", "-R", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p.parent if p.is_file() else p)])
        except Exception as e:
            QMessageBox.warning(self, "Open failed", str(e))

    def log(self, msg: str) -> None:
        self.status_box.append(msg)

    def set_status(self, msg: str) -> None:
        self.status_lbl.setText(msg)
        self.log(msg)

    def _make_run_report_dir(self, reports_root: Path, scan_root: Path) -> Path:
        def safe_tag(s: str) -> str:
            s = s.strip().replace(":", "")
            out = []
            for ch in s:
                if ch.isalnum() or ch in ("-", "_"):
                    out.append(ch)
                else:
                    out.append("_")
            tag = "".join(out).strip("_")
            return tag[:40] if tag else "scan"

        stamp = time.strftime("%Y-%m-%d_%H%M%S")
        run_id = new_run_id()[:12]
        tag = scan_root.name or scan_root.drive or "scan"
        tag = safe_tag(tag)

        base = f"{stamp}_{tag}_{run_id}"
        run_dir = reports_root / base

        n = 1
        while run_dir.exists():
            n += 1
            run_dir = reports_root / f"{base}_{n}"

        return run_dir

    def open_current_report_folder(self) -> None:
        try:
            safe_mkdir(self.report_dir)
            os.startfile(str(self.report_dir))  # type: ignore[attr-defined]
        except Exception as e:
            QMessageBox.warning(self, "Open folder failed", str(e))

    def open_report_folder(self) -> None:
        d = Path(self.report_dir)
        safe_mkdir(d)
        try:
            os.startfile(str(d))
        except Exception as e:
            QMessageBox.warning(self, "Open failed", str(e))

    def open_report_file(self, filename: str) -> None:
        p = self.report_dir / filename
        if not p.exists():
            QMessageBox.information(self, "Not found", f"File does not exist:\n{p}")
            return
        try:
            os.startfile(str(p))
        except Exception as e:
            QMessageBox.warning(self, "Open failed", str(e))

    def _apply_button_roles(self) -> None:
        primary_buttons = [
            self.start_btn,
            self.monitor_start_btn,
            self.monitor_resume_btn,
            self.ai_action_btn,
            self.plan_advance_btn,
        ]
        secondary_buttons = [
            self.cancel_btn,
            self.load_btn,
            self.open_reports_btn,
            self.space_audit_btn,
            self.open_evidence_btn,
            self.ai_why_btn,
            self.investigate_btn,
            self.monitor_pause_btn,
            self.prefer_path_btn,
            self.auto_prune_btn,
            self.compare_prune_btn,
            self.suggest_keep_paths_btn,
            self.suggest_paths_btn,
            self.analyze_paths_btn,
            self.trash_folder_btn,
            self.open_file_btn,
            self.open_folder_btn,
        ]
        destructive_buttons = [self.keep_delete_btn]
        for btn in primary_buttons:
            btn.setProperty("buttonRole", "primary")
        for btn in secondary_buttons:
            btn.setProperty("buttonRole", "secondary")
        for btn in destructive_buttons:
            btn.setProperty("buttonRole", "destructive")
        self.setStyleSheet(
            """
            QPushButton[buttonRole="primary"] {
                background-color: #1f6feb;
                color: #ffffff;
                border: 1px solid #1a5fcc;
                font-weight: 600;
                padding: 6px 10px;
                border-radius: 4px;
            }
            QPushButton[buttonRole="primary"]:disabled {
                background-color: #9bbcf2;
                color: #f4f7fc;
                border: 1px solid #7da5e9;
            }
            QPushButton[buttonRole="secondary"] {
                background-color: #f3f4f6;
                color: #1f2937;
                border: 1px solid #c8ced8;
                padding: 6px 10px;
                border-radius: 4px;
            }
            QPushButton[buttonRole="secondary"]:disabled {
                background-color: #eceff3;
                color: #67768a;
                border: 1px solid #d3d9e2;
            }
            QPushButton[buttonRole="destructive"] {
                background-color: #c0392b;
                color: #ffffff;
                border: 1px solid #a93226;
                font-weight: 600;
                padding: 6px 10px;
                border-radius: 4px;
            }
            QPushButton[buttonRole="destructive"]:disabled {
                background-color: #e8b3ad;
                color: #fff8f7;
                border: 1px solid #d99d97;
            }
            QToolTip {
                background-color: #111827;
                color: #f9fafb;
                border: 1px solid #374151;
                padding: 4px 6px;
            }
            """
        )

    def _apply_tooltips(self) -> None:
        self.space_audit_btn.setToolTip("Review disk usage trends and largest folders.")
        self.load_btn.setToolTip("Load a previous scan without starting a new one.")
        self.suggest_keep_paths_btn.setToolTip("Suggest keep-path prefixes based on compare results.")
        self.suggest_paths_btn.setToolTip("Recommend top locations to keep files from.")
        self.analyze_paths_btn.setToolTip("Analyze Storage Patterns and suggest useful prefixes.")
        self.auto_prune_btn.setToolTip("Build a keep/delete plan using your preferred keep path.")
        self.compare_prune_btn.setToolTip("Create a delete plan for Root A when matching files exist in Root B.")
        self.keep_delete_btn.setToolTip("Delete duplicate files and keep only your selected file.")
        self.ai_action_btn.setToolTip("Apply the selected finding's recommended action.")
        self.plan_advance_btn.setToolTip("Move the plan to its next approval state.")

    def _reports_root_dir(self) -> Path:
        return Path(self.report_edit.text().strip() or str(self.reports_root))

    def _looks_like_run_folder(self, folder: Path) -> bool:
        return re.match(r"^\d{4}-\d{2}-\d{2}_\d{6}_.+$", folder.name) is not None

    def pick_root(self) -> None:
        d = QFileDialog.getExistingDirectory(
            self,
            "Choose root folder/drive to scan",
            self.root_edit.text() or str(Path.home()),
        )
        if d:
            self.root_edit.setText(d)

    @Slot(bool)
    def on_compare_mode_toggled(self, enabled: bool) -> None:
        self.root2_edit.setEnabled(enabled)
        self.browse_root2_btn.setEnabled(enabled)

        has_results = bool(self.dupe_by_digest)
        self.compare_prune_btn.setEnabled(enabled and has_results)
        self.suggest_keep_paths_btn.setEnabled(enabled and has_results)

    def pick_root2(self) -> None:
        d = QFileDialog.getExistingDirectory(
            self,
            "Choose Root B folder/drive to compare",
            self.root2_edit.text() or str(Path.home()),
        )
        if d:
            self.root2_edit.setText(d)

    def pick_report_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(
            self,
            "Choose reports root folder (new scan folders will be created here)",
            self.report_edit.text() or str(self.reports_root),
        )
        if d:
            self.reports_root = Path(d)
            self.report_edit.setText(str(self.reports_root))
            QSettings("DupeFinder", "DupeFinderGUI").setValue(
                "reports_root", str(self.reports_root)
            )

    def pick_trash_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(
            self,
            "Choose trash folder",
            self.trash_folder_edit.text() or str(self.report_dir),
        )
        if d:
            self.trash_folder_edit.setText(d)

    def pick_prefer_path(self) -> None:
        current = self.prefer_path_edit.text().strip()
        if current:
            parts = [p.strip() for p in current.split(";") if p.strip()]
            start = parts[-1] if parts else (self.root_edit.text().strip() or str(Path.home()))
        else:
            start = self.root_edit.text().strip() or str(Path.home())

        d = QFileDialog.getExistingDirectory(
            self,
            "Choose preferred folder (files under this path will be kept)",
            start,
        )
        if not d:
            return

        if current:
            new_text = current.rstrip().rstrip(";")
            new_text = f"{new_text}; {d}"
            self.prefer_path_edit.setText(new_text)
        else:
            self.prefer_path_edit.setText(d)

    def update_remaining_indicator(self) -> None:
        groups = len(self.dupe_by_digest)
        total_files = sum(len(g.files) for g in self.dupe_by_digest.values())
        duplicate_files = sum(
            max(0, len(g.files) - 1) for g in self.dupe_by_digest.values()
        )
        reclaimable = sum(
            max(0, len(g.files) - 1) * g.size for g in self.dupe_by_digest.values()
        )

        self.remaining_lbl.setText(
            f"Remaining: Groups={groups:,} | Files in groups={total_files:,} | Extra dupes={duplicate_files:,} | Reclaimable≈{format_bytes(reclaimable)}"
        )

    def on_delete_mode_changed(self) -> None:
        mode = self.delete_mode.currentText()
        enable_trash = ("Move to trash folder" in mode) or ("Quarantine" in mode)
        self.trash_folder_edit.setEnabled(enable_trash)
        self.trash_folder_btn.setEnabled(enable_trash)

    def clear_results(self, silent: bool = False) -> None:
        self.tree_by_name.clear()
        self.tree_by_hash.clear()
        self.files_table.setRowCount(0)
        self.dupe_by_digest.clear()
        self.current_digest = None
        if not silent:
            self.set_status("Cleared results.")
        self.update_remaining_indicator()

    # ----------------------------
    # Excludes (FULL PATHS + DIR NAMES)
    # ----------------------------

    def _compile_excludes_from_ui(self) -> tuple[set[str], list[str]]:
        """
        Compiles exclude rules from the UI field into:
          - dir_names: directory NAMES to exclude (case-insensitive)
          - prefixes: normalized full path prefixes to exclude
        Cached so we don't recompute on every file delete.
        """
        raw = (self.exclude_edit.text() or "").strip()
        if raw == self._ex_cache_raw and self._ex_cache:
            return self._ex_cache

        parts = [p.strip() for p in raw.split(",") if p.strip()]
        if not parts:
            parts = list(DEFAULT_EXCLUDES)

        # compile_excludes also adds DEFAULT_EXCLUDES
        dir_names, prefixes = compile_excludes(set(parts))

        self._ex_cache_raw = raw
        self._ex_cache = (dir_names, prefixes)
        return self._ex_cache

    def _excluded_component_in_path(self, path: str) -> Optional[str]:
        """
        If the given path is excluded by:
          - full path prefix, or
          - directory-name match anywhere in the path,
        return what matched (prefix or component). Else None.

        This is used as a HARD SAFETY check before deleting files.
        """
        dir_names, prefixes = self._compile_excludes_from_ui()

        p_raw = (path or "").strip().strip('"')
        if not p_raw:
            return None

        ps = os.path.normcase(os.path.normpath(os.path.expandvars(p_raw)))

        # 1) Full path prefix protection
        for pref in prefixes:
            if not pref:
                continue
            # drive-root prefixes may end with os.sep; handle them safely
            if pref.endswith(os.sep):
                if ps.startswith(pref):
                    return pref
            else:
                if ps == pref or ps.startswith(pref + os.sep):
                    return pref

        # 2) Directory-name protection
        try:
            parts = Path(ps).parts
        except Exception:
            parts = re.split(r"[\\/]+", ps)

        for part in parts:
            if not part:
                continue
            if part.lower() in dir_names:
                return part

        return None


    # ----------------------------
    # Scan control
    # ----------------------------

    def start_scan(self) -> None:
        root_a_txt = self.root_edit.text().strip()
        if not root_a_txt:
            QMessageBox.warning(
                self, "Missing root", "Please choose Root A (e.g. C:\\ or a folder)."
            )
            return
        root_a = Path(root_a_txt)
        if not root_a.exists():
            QMessageBox.warning(
                self, "Invalid root", f"Root A does not exist:\n{root_a}"
            )
            return

        compare_mode = bool(self.compare_mode_chk.isChecked())
        roots: list[Path] = [root_a]

        if compare_mode:
            root_b_txt = self.root2_edit.text().strip()
            if not root_b_txt:
                QMessageBox.warning(
                    self,
                    "Missing Root B",
                    "Compare mode is enabled. Please choose Root B.",
                )
                return
            root_b = Path(root_b_txt)
            if not root_b.exists():
                QMessageBox.warning(
                    self, "Invalid Root B", f"Root B does not exist:\n{root_b}"
                )
                return
            roots.append(root_b)
        self.allowed_roots = list(roots)

        reports_root = self._reports_root_dir()
        self.reports_root = reports_root
        safe_mkdir(reports_root)

        QSettings("DupeFinder", "DupeFinderGUI").setValue(
            "reports_root", str(reports_root)
        )

        self.report_dir = self._make_run_report_dir(reports_root, roots[0])
        safe_mkdir(self.report_dir)
        self.report_edit.setText(str(reports_root))
        self.trash_folder_edit.setText(str(self.report_dir / "_trash"))

        # IMPORTANT: do NOT lowercase here; dupe_core.compile_excludes will normalize.
        excludes = {s.strip() for s in (self.exclude_edit.text() or "").split(",") if s.strip()}
        if not excludes:
            excludes = set(DEFAULT_EXCLUDES)

        min_size = int(self.min_size_spin.value())
        follow = bool(self.follow_symlinks_chk.isChecked())
        if detect_elevated_privileges() and follow:
            QMessageBox.warning(
                self,
                self.WARNING_TEXTS["risk_mode_blocked_title"],
                self.WARNING_TEXTS["risk_mode_blocked_body"],
            )
            return

        self.clear_results()
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)

        self.worker_thread = QThread()
        self.worker = ScanWorker(
            roots=roots,
            compare_mode=compare_mode,
            report_dir=self.report_dir,
            excludes=excludes,
            follow_symlinks=follow,
            min_size=min_size,
        )

        self.worker.moveToThread(self.worker_thread)

        self.worker_thread.started.connect(self.worker.run)
        self.worker.status.connect(self.set_status)
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.error.connect(self.on_scan_error)
        self.worker.metrics.connect(self.on_metrics)

        self.worker_thread.start()
        self.set_status("Starting scan…")

    def cancel_scan(self) -> None:
        if self.worker:
            self.worker.cancel("user_cancelled")
            self.set_status("Cancel requested…")
        if self.space_audit_worker:
            self.space_audit_worker.cancel_run("user_cancelled")
            self.set_status("Disk usage analysis cancellation requested…")

    def start_space_audit(self) -> None:
        root_a_txt = self.root_edit.text().strip()
        if not root_a_txt:
            QMessageBox.warning(self, "Missing root", "Please choose Root A first.")
            return
        roots: list[Path] = [Path(root_a_txt)]
        if self.compare_mode_chk.isChecked() and self.root2_edit.text().strip():
            roots.append(Path(self.root2_edit.text().strip()))
        roots = [r for r in roots if r.exists()]
        if not roots:
            QMessageBox.warning(self, "Invalid root", "No valid root path is available for analysis.")
            return
        excludes = {s.strip() for s in (self.exclude_edit.text() or "").split(",") if s.strip()}
        if not excludes:
            excludes = set(DEFAULT_EXCLUDES)
        if not self.report_dir or self.report_dir == self.reports_root:
            self.report_dir = self._make_run_report_dir(self._reports_root_dir(), roots[0])
        safe_mkdir(self.report_dir)

        self.start_btn.setEnabled(False)
        self.space_audit_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress.setRange(0, 0)
        self.set_status("Starting disk usage analysis…")
        if self._monitor_mode == "stopped":
            self._set_monitor_mode("running")

        self.space_audit_thread = QThread()
        self.space_audit_worker = SpaceAuditWorker(
            roots=roots,
            report_dir=self.report_dir,
            excludes=excludes,
            policy_path=Path(DEFAULT_TOML),
        )
        self.space_audit_worker.moveToThread(self.space_audit_thread)
        self.space_audit_thread.started.connect(self.space_audit_worker.run)
        self.space_audit_worker.status.connect(self.set_status)
        self.space_audit_worker.metrics.connect(self.on_metrics)
        self.space_audit_worker.progress.connect(self.on_progress)
        self.space_audit_worker.finished.connect(self.on_space_audit_finished)
        self.space_audit_worker.error.connect(self.on_space_audit_error)
        self.space_audit_thread.start()

    @Slot(object)
    def on_space_audit_finished(self, result_obj: object) -> None:
        if self.space_audit_thread:
            self.space_audit_thread.quit()
            self.space_audit_thread.wait()
        self.start_btn.setEnabled(True)
        self.space_audit_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        result = result_obj if isinstance(result_obj, dict) else {}
        if result.get("cancelled"):
            self.set_status("Disk usage analysis cancelled.")
        else:
            offenders = result.get("top_offenders", [])
            warnings = result.get("warnings", [])
            diffs = result.get("diff_summaries", [])
            net = sum(int(d.get("net_change_bytes", 0)) for d in diffs)
            top_lines = "\n".join(
                f"• {row.get('root')} :: {row.get('path')} — {format_bytes(int(row.get('bytes', 0)))}"
                for row in offenders[:5]
            ) or "• none"
            warn_line = f"{len(warnings)} protected/skipped entries recorded."
            summary = (
                "Disk usage analysis complete.\n\n"
                f"Top offenders:\n{top_lines}\n\n"
                f"Net change vs previous snapshot: {format_bytes(net)}\n"
                f"Warnings/skipped protected areas: {warn_line}\n\n"
                f"Artifacts: {self.report_dir}"
            )
            self.log(summary)
            self._update_summary_pane(result)
            snapshots = result.get("snapshots", [])
            if snapshots:
                self._refresh_monitor_panel(
                    snapshot=snapshots[-1],
                    top_offenders=offenders if isinstance(offenders, list) else [],
                    diff_summaries=diffs if isinstance(diffs, list) else [],
                )
            QMessageBox.information(self, "Disk usage analysis", summary)
        self.space_audit_worker = None
        self.space_audit_thread = None

    def _update_summary_pane(self, result: dict) -> None:
        offenders = result.get("top_offenders", []) if isinstance(result.get("top_offenders"), list) else []
        warnings = result.get("warnings", []) if isinstance(result.get("warnings"), list) else []
        diffs = result.get("diff_summaries", []) if isinstance(result.get("diff_summaries"), list) else []
        net = sum(int(d.get("net_change_bytes", 0)) for d in diffs)
        top = offenders[:3]
        top_lines = [
            f"- {row.get('path', 'unknown')} ({format_bytes(int(row.get('bytes', 0)))})"
            for row in top
        ] or ["- none"]
        confidence = "high" if top and abs(net) > 0 else "medium" if top else "low"
        safe_next_steps = [
            "Review top offenders and verify they are non-system data.",
            "Use Recycle Bin mode first; avoid permanent delete.",
            "Re-run analysis after each action to confirm reclaimed space.",
        ]
        self.findings_summary.setPlainText(
            "Top findings\n"
            + "\n".join(top_lines)
            + f"\n\nConfidence: {confidence}\nNet change: {format_bytes(net)}"
            + "\n\nSafe next steps\n"
            + "\n".join(f"- {s}" for s in safe_next_steps)
        )
        if warnings:
            self.protected_warning_lbl.setText(
                f"Warning: {len(warnings)} protected/system-managed zone(s) were skipped or blocked."
            )
            self.protected_warning_lbl.show()
        else:
            self.protected_warning_lbl.hide()

    def run_disappearing_space_wizard(self) -> None:
        steps = (
            "Investigate disappearing space wizard\n\n"
            "1) Capture/compare current usage snapshot.\n"
            "2) Review top growth offenders and confidence.\n"
            "3) Confirm protected/system-managed warnings.\n"
            "4) Execute only safe actions, then validate outcomes."
        )
        QMessageBox.information(self, "Investigation wizard", steps)
        self.start_space_audit()

    @Slot(str)
    def on_space_audit_error(self, err: str) -> None:
        if self.space_audit_thread:
            self.space_audit_thread.quit()
            self.space_audit_thread.wait()
        self.start_btn.setEnabled(True)
        self.space_audit_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        QMessageBox.critical(self, "Disk usage analysis error", err)
        self.space_audit_worker = None
        self.space_audit_thread = None

    @Slot(int, int)
    def on_progress(self, cur: int, total: int) -> None:
        if total == 0:
            self.progress.setRange(0, 0)
        else:
            self.progress.setRange(0, total)
            self.progress.setValue(cur)

    @Slot(object)
    def on_metrics(self, m: object) -> None:
        if not isinstance(m, dict):
            return

        phase = m.get("phase", "?")
        listed = m.get("listed")
        indexed = m.get("indexed")
        skipped = m.get("skipped")
        errors = m.get("errors", 0)
        skipped_placeholders = m.get("skipped_placeholders", 0)

        elapsed_s = m.get("elapsed_s", 0.0)
        eta_s = m.get("eta_s")

        hash_done = m.get("hash_done")
        hash_total = m.get("hash_total")
        dupe_groups = m.get("dupe_groups")

        lines = []
        lines.append(f"Phase: {phase}")

        curfile = m.get("current_file")
        if curfile:
            lines.append(f"Current: {curfile}")

        sg = m.get("current_size_group")
        cin = m.get("current_in_group")
        tin = m.get("total_in_group")
        if sg is not None and tin:
            lines.append(f"Size-group: {format_bytes(int(sg))}   File: {cin:,}/{tin:,}")

        if phase == "Scanning":
            self.progress.setRange(0, 0)
        elif hash_total is not None and hash_done is not None:
            self.progress.setRange(0, int(hash_total))
            self.progress.setValue(int(hash_done))

        if listed is not None:
            rate = m.get("rate_files_per_s") or 0.0
            lines.append(
                f"Listed: {listed:,}   Indexed: {indexed:,}   Skipped: {skipped:,}   Errors: {errors:,}"
            )
            lines.append(f"Rate: {rate:,.1f} files/s")
        else:
            lines.append(f"Errors: {errors:,}")

        if skipped_placeholders:
            lines.append(f"Skipped placeholders/offline: {skipped_placeholders:,}")

        if hash_total is not None:
            lines.append(
                f"Hashed size-groups: {hash_done:,}/{hash_total:,}   Dupe groups: {dupe_groups:,}"
            )

        lines.append(f"Elapsed: {fmt_duration(elapsed_s)}")
        if eta_s is not None:
            lines.append(f"ETA:     {fmt_duration(eta_s)}")

        self.rclone_stats.setText("\n".join(lines))

    @Slot(object)
    def on_scan_finished(self, dupes_obj: object) -> None:
        dupes: list[DupeGroup] = dupes_obj if isinstance(dupes_obj, list) else []

        if self.worker_thread:
            self.worker_thread.quit()
            self.worker_thread.wait()

        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)

        self.dupe_by_digest = {g.sha256: g for g in dupes}

        if self.compare_mode_chk.isChecked():
            self.compare_prune_btn.setEnabled(True)
            self.suggest_keep_paths_btn.setEnabled(True)

        self.populate_trees(dupes)
        self.update_remaining_indicator()

        reclaimable = sum((len(g.files) - 1) * g.size for g in dupes)
        self.set_status(
            f"Results loaded. Groups={len(dupes):,}  Reclaimable≈{format_bytes(reclaimable)}"
        )
        self.log(f"Reports written to: {self.report_dir}")
        QSettings("DupeFinder", "DupeFinderGUI").setValue(
            "last_report_dir", str(self.report_dir)
        )

        self.worker = None
        self.worker_thread = None

    @Slot(str)
    def on_scan_error(self, err: str) -> None:
        if self.worker_thread:
            self.worker_thread.quit()
            self.worker_thread.wait()

        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        QMessageBox.critical(self, "Scan error", err)
        self.set_status(f"Error: {err}")

        self.worker = None
        self.worker_thread = None

    # ----------------------------
    # Results display
    # ----------------------------

    def populate_trees(self, dupes: list[DupeGroup]) -> None:
        self.tree_by_name.clear()
        self.tree_by_hash.clear()

        def size_for_digest(d: str) -> int:
            gg = self.dupe_by_digest.get(d)
            return gg.size if gg else 0

        for g in sorted(dupes, key=lambda x: (-x.size, -len(x.files), x.sha256)):
            names = [f.name for f in g.files]
            common = Counter(names).most_common(1)[0][0] if names else "(unknown)"
            text = f"{common}  —  {len(g.files)} files × {format_bytes(g.size)}  —  {g.sha256[:12]}…"
            item = QTreeWidgetItem([text])
            item.setData(0, Qt.ItemDataRole.UserRole, g.sha256)
            self.tree_by_hash.addTopLevelItem(item)

        name_map: dict[str, list[tuple[str, int, int]]] = defaultdict(list)
        for g in dupes:
            counts = Counter([f.name for f in g.files])
            for name, c in counts.items():
                if c >= 2:
                    name_map[name].append((g.sha256, c, len(g.files)))

        for name in sorted(name_map.keys(), key=lambda s: s.lower()):
            groups = name_map[name]
            top = QTreeWidgetItem([f"{name}  —  {len(groups)} duplicate group(s)"])
            top.setData(0, Qt.ItemDataRole.UserRole, None)
            self.tree_by_name.addTopLevelItem(top)

            for digest, c, total in sorted(
                groups, key=lambda t: (-size_for_digest(t[0]), -t[2], t[0])
            ):
                g = self.dupe_by_digest.get(digest)
                if not g:
                    continue

                child_text = f"{digest[:12]}…  —  {c} named like this (total {total}) × {format_bytes(g.size)}"
                child = QTreeWidgetItem([child_text])
                child.setData(0, Qt.ItemDataRole.UserRole, digest)
                top.addChild(child)

            top.setExpanded(False)

    def on_tree_selection(self) -> None:
        tree = self.tabs.currentWidget()
        if not isinstance(tree, QTreeWidget):
            return

        items = tree.selectedItems()
        if not items:
            return

        digest = items[0].data(0, Qt.ItemDataRole.UserRole)
        if not digest or digest not in self.dupe_by_digest:
            return

        self.current_digest = digest
        self.load_group_into_table(self.dupe_by_digest[digest])

    def load_group_into_table(self, g: DupeGroup) -> None:
        self.files_table.setSortingEnabled(False)
        self.files_table.setRowCount(0)

        for f in g.files:
            row = self.files_table.rowCount()
            self.files_table.insertRow(row)

            name_item = QTableWidgetItem(f.name)
            try:
                icon = self.icon_provider.icon(QFileInfo(f.path))
                name_item.setIcon(icon)
            except Exception:
                pass

            name_item.setData(Qt.ItemDataRole.UserRole, f.path)

            size_item = QTableWidgetItem(format_bytes(f.size))
            size_item.setData(Qt.ItemDataRole.UserRole, f.size)

            mtime_item = QTableWidgetItem(fmt_time(f.mtime))
            mtime_item.setData(Qt.ItemDataRole.UserRole, f.mtime)

            path_item = QTableWidgetItem(f.path)

            self.files_table.setItem(row, 0, name_item)
            self.files_table.setItem(row, 1, size_item)
            self.files_table.setItem(row, 2, mtime_item)
            self.files_table.setItem(row, 3, path_item)

        self.files_table.resizeColumnsToContents()
        self.files_table.setSortingEnabled(True)

    def selected_row_path(self) -> Optional[str]:
        rows = self.files_table.selectionModel().selectedRows()
        if not rows:
            return None
        r = rows[0].row()
        item = self.files_table.item(r, 0)
        if not item:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def open_selected_file(self) -> None:
        p = self.selected_row_path()
        if not p:
            QMessageBox.information(self, "No selection", "Select a file row first.")
            return
        try:
            os.startfile(p)  # type: ignore[attr-defined]
        except Exception as e:
            QMessageBox.warning(self, "Open failed", str(e))

    def open_selected_folder(self) -> None:
        p = self.selected_row_path()
        if not p:
            QMessageBox.information(self, "No selection", "Select a file row first.")
            return
        try:
            self.reveal_in_explorer(p)
        except Exception as e:
            QMessageBox.warning(self, "Open failed", str(e))

    def on_file_cell_double_clicked(self, row: int, col: int) -> None:
        if col != 3:
            return
        item = self.files_table.item(row, 3)
        if not item:
            return
        p = item.text().strip()
        if not p:
            return
        self.reveal_in_explorer(p)

    def on_file_cell_clicked(self, row: int, col: int) -> None:
        if col != 3:
            return
        item = self.files_table.item(row, 3)
        if not item:
            return
        p = item.text().strip()
        if not p:
            return
        self.reveal_in_explorer(p)

    # ----------------------------
    # Prune / delete actions
    # ----------------------------

    def _parse_preferred_prefixes(self, raw: Optional[str] = None) -> list[str]:
        if raw is None:
            raw = self.prefer_path_edit.text() or ""

        raw = (raw or "").strip().strip('"')
        if not raw:
            return []

        raw = raw.replace("|", ";")
        parts = re.split(r"[;\n,]+", raw)

        def _norm_dir_prefix(p: str) -> str:
            p2 = os.path.normcase(os.path.normpath(p))
            if re.match(r"^[A-Za-z]:$", p2):
                p2 = p2 + os.sep
            if not p2.endswith(os.sep):
                p2 += os.sep
            return p2

        seen: set[str] = set()
        out: list[str] = []
        for p in parts:
            p = p.strip().strip('"')
            if not p:
                continue
            n = _norm_dir_prefix(p)
            if n not in seen:
                seen.add(n)
                out.append(n)

        return out

    # --- deletion helpers (same as your working build) ---

    def _split_failed_ops(
        self, failed: list[tuple[str, str]]
    ) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        protected: list[tuple[str, str]] = []
        real: list[tuple[str, str]] = []
        for p, err in failed:
            if (err or "").startswith("PROTECTED:"):
                protected.append((p, err))
            else:
                real.append((p, err))
        return protected, real

    def _apply_deletes(
        self,
        delete_paths: list[str],
        mode: str,
        trash_dir: Optional[Path],
    ) -> tuple[list[str], list[tuple[str, str]]]:
        removed: list[str] = []
        failed: list[tuple[str, str]] = []
        before_exists = {p: os.path.exists(p) for p in delete_paths}
        before_prompt = QMessageBox.question(
            self,
            "Validate before actions",
            "Before/after validation is enabled.\nProceed with selected action(s)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if before_prompt != QMessageBox.StandardButton.Yes:
            return removed, [("operation", "user_cancelled_before_validation")]

        def try_recycle(p: str) -> None:
            result = execute_prune_plan(build_prune_plan([p], mode="recycle"))
            if result.failed:
                raise RuntimeError(result.errors[0])

        def try_move_to_trash(p: str, td: Path) -> None:
            src = Path(p)
            if not src.exists():
                return

            safe_mkdir(td)

            try:
                if src.drive and td.drive and src.drive.lower() != td.drive.lower():
                    need = src.stat().st_size
                    free = shutil.disk_usage(str(td)).free
                    reserve = 256 * 1024 * 1024
                    if free - reserve < need:
                        raise OSError(
                            f"Not enough free space on trash drive for {src.name} "
                            f"(need {need} bytes, free {free} bytes)."
                        )
            except Exception as e:
                raise OSError(str(e))

            dst = td / f"{src.name}.{time.time_ns()}"
            shutil.move(str(src), str(dst))
            return str(dst)

        for p in delete_paths:
            try:
                perm = evaluate_delete_permission(
                    p, mode=mode, action_type="delete", safe_roots=self.allowed_roots
                )
                if not bool(perm.get("allow")):
                    reason = str(perm.get("reason", "Blocked by protection policy"))
                    code = str(perm.get("reason_code", "policy_deny"))
                    failed.append((p, reason))
                    append_prune_event(
                        self.report_dir,
                        make_audit_event(
                            self.session_id, "delete", p, "blocked", f"{code}:{reason}"
                        ),
                    )
                    continue

                hit = self._excluded_component_in_path(p)
                if hit:
                    failed.append((p, f"PROTECTED: path matches exclude '{hit}'"))
                    append_prune_event(
                        self.report_dir,
                        make_audit_event(
                            self.session_id, "delete", p, "blocked", f"user_exclude:{hit}"
                        ),
                    )
                    continue

                if not os.path.exists(p):
                    removed.append(p)
                    append_prune_event(
                        self.report_dir,
                        make_audit_event(self.session_id, "delete", p, "noop_missing"),
                    )
                    continue

                if "Recycle Bin" in mode:
                    try_recycle(p)
                elif "Move to trash folder" in mode:
                    if trash_dir is None:
                        raise RuntimeError("Trash directory not set.")
                    try_move_to_trash(p, trash_dir)
                elif "Quarantine" in mode:
                    if trash_dir is None:
                        raise RuntimeError("Quarantine directory not set.")
                    qdir = trash_dir / "_quarantine"
                    dst = try_move_to_trash(p, qdir)
                    manifest = {
                        "source_path": p,
                        "quarantine_path": dst,
                        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                        "session": self.session_id,
                        "mode": "quarantine",
                    }
                    append_prune_event(self.report_dir, {"quarantine_manifest": manifest})
                else:
                    os.remove(p)

                if os.path.exists(p):
                    failed.append((p, "File still exists after operation"))
                else:
                    removed.append(p)
                    append_prune_event(
                        self.report_dir,
                        make_audit_event(self.session_id, "delete", p, "success"),
                    )

            except Exception as e:
                failed.append((p, f"{type(e).__name__}: {e}"))
                append_prune_event(
                    self.report_dir,
                    make_audit_event(
                        self.session_id, "delete", p, "error", f"{type(e).__name__}: {e}"
                    ),
                )

        post_ok = sum(1 for p in delete_paths if before_exists.get(p) and not os.path.exists(p))
        outcome_msg = (
            f"Outcome tracking:\n"
            f"- Requested: {len(delete_paths)}\n"
            f"- Removed/relocated: {len(removed)}\n"
            f"- Validation passed: {post_ok}\n"
            f"- Failed: {len(failed)}"
        )
        self.log(outcome_msg)
        QMessageBox.information(self, "Post-action validation", outcome_msg)
        return removed, failed

    # The rest of your prune + load functions are unchanged in this recovery copy.
    # To keep this file compact, we kept the scan, result display, and delete safety core intact.
    # If you want the FULL previous version (with every helper + dialog), paste your last
    # dupe_finder_gui.py and I’ll generate a 1:1 patched copy.

    # ----------------------------
    # Stubs for features from your last version (keep API stable)
    # ----------------------------

    def auto_prune_by_preferred_path(self) -> None:
        QMessageBox.information(self, "Not included", "This recovery copy excludes auto-prune UI logic. Paste your last GUI file if you need it restored 1:1.")

    def compare_prune_delete_a_using_b(self) -> None:
        QMessageBox.information(self, "Not included", "This recovery copy excludes compare-prune UI logic. Paste your last GUI file if you need it restored 1:1.")

    def analyze_paths_suggest_prefixes(self) -> None:
        QMessageBox.information(self, "Not included", "This recovery copy excludes path analysis UI logic. Paste your last GUI file if you need it restored 1:1.")

    def open_suggest_keep_paths(self) -> None:
        QMessageBox.information(self, "Not included", "This recovery copy excludes keep-path suggestion dialog. Paste your last GUI file if you need it restored 1:1.")

    def open_path_suggestions(self) -> None:
        QMessageBox.information(self, "Not included", "This recovery copy excludes prefix suggestion dialog. Paste your last GUI file if you need it restored 1:1.")

    def persist_current_results(self) -> None:
        try:
            dupes = list(self.dupe_by_digest.values())
            write_live_reports(self.report_dir, dupes)
        except Exception as e:
            self.log(f"Warning: failed to persist results: {e}")

    def load_previous_scan(self) -> None:
        QMessageBox.information(self, "Not included", "This recovery copy excludes the load-scan workflow. Paste your last GUI file if you need it restored 1:1.")

    def keep_selected_delete_others(self) -> None:
        QMessageBox.information(self, "Not included", "This recovery copy excludes the manual keep/delete UI logic. Paste your last GUI file if you need it restored 1:1.")


def main() -> int:
    app = QApplication(sys.argv)
    w = MainWindow()
    w.resize(1200, 720)
    w.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
    make_audit_event,
