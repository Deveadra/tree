from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QRect
    from PySide6.QtGui import QImage
    from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QWidget
except Exception as exc:  # pragma: no cover - environment-specific skip
    pytest.skip(f"PySide6/Qt runtime unavailable: {exc}", allow_module_level=True)

from dupe_finder_gui import MainWindow

VIEWPORTS = [(1366, 768), (1536, 864), (1920, 1080)]
SNAPSHOT_DIR = Path("tests/fixtures/ui_snapshots")


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _intersects(a: QWidget, b: QWidget) -> bool:
    a_rect = QRect(a.mapToGlobal(a.rect().topLeft()), a.size())
    b_rect = QRect(b.mapToGlobal(b.rect().topLeft()), b.size())
    return a_rect.intersects(b_rect)


def _assert_nonempty_image(path: Path) -> None:
    image = QImage(str(path))
    assert not image.isNull(), f"snapshot is unreadable: {path}"
    assert image.width() > 200 and image.height() > 100


@pytest.mark.parametrize("width,height", VIEWPORTS)
def test_layout_integrity_across_viewports(width: int, height: int) -> None:
    app = _app()
    window = MainWindow()
    window.resize(width, height)
    window.show()
    app.processEvents()

    key_widgets = [
        window.basic_group,
        window.adv_group,
        window.root_edit,
        window.report_edit,
        window.main_splitter,
        window.dupe_table,
        window.file_table,
    ]

    for widget in key_widgets:
        assert widget.isVisible(), f"{widget} should be visible at {width}x{height}"
        assert widget.width() > 0 and widget.height() > 0

    assert not _intersects(window.basic_group, window.adv_group)

    controls = [window.root_edit, window.root2_edit, window.report_edit]
    for control in controls:
        assert control.height() >= 30

    for label in [window.root1_lbl, window.root2_lbl, window.report_lbl]:
        assert isinstance(label, QLabel)
        text_width = label.fontMetrics().horizontalAdvance(label.text().strip())
        assert text_width <= label.contentsRect().width() + 20

    for line_edit in controls:
        assert isinstance(line_edit, QLineEdit)
        sample = line_edit.placeholderText() or line_edit.text() or "WWWWWWWWWW"
        assert line_edit.fontMetrics().horizontalAdvance(sample[:20]) <= line_edit.contentsRect().width() + 40

    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    top_path = SNAPSHOT_DIR / f"{width}x{height}_top_setup.png"
    results_path = SNAPSHOT_DIR / f"{width}x{height}_results_split.png"
    assert window.tier1_block.grab().save(str(top_path))
    assert window.main_splitter.grab().save(str(results_path))
    _assert_nonempty_image(top_path)
    _assert_nonempty_image(results_path)

    window.close()
