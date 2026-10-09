"""Reusable widgets: cards, pills, verdict gauge, filterable tables, drop zone."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QModelIndex, QPoint, QRect, QRectF, QSize, QSortFilterProxyModel, Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QStandardItem,
    QStandardItemModel,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from emailicioso.core.models import Severity
from emailicioso.ui import theme

COLOR_ROLE = Qt.ItemDataRole.UserRole + 1
PAYLOAD_ROLE = Qt.ItemDataRole.UserRole + 2
SORT_ROLE = Qt.ItemDataRole.UserRole + 3


# --------------------------------------------------------------------------- helpers


def label(text: str = "", object_name: str = "", wrap: bool = False, selectable: bool = False) -> QLabel:
    lb = QLabel(text)
    if object_name:
        lb.setObjectName(object_name)
    lb.setWordWrap(wrap)
    if selectable:
        lb.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lb


def button(text: str, slot: Callable | None = None, primary: bool = False, flat: bool = False,
           tooltip: str = "") -> QPushButton:
    b = QPushButton(text)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    if primary:
        b.setProperty("primary", True)
    if flat:
        b.setProperty("flat", True)
    if tooltip:
        b.setToolTip(tooltip)
    if slot is not None:
        b.clicked.connect(slot)
    return b


def hbox(*widgets: Any, spacing: int = 8, margins: tuple[int, int, int, int] = (0, 0, 0, 0)) -> QHBoxLayout:
    lay = QHBoxLayout()
    lay.setSpacing(spacing)
    lay.setContentsMargins(*margins)
    for w in widgets:
        if w is None:
            lay.addStretch(1)
        elif isinstance(w, int):
            lay.addSpacing(w)
        elif isinstance(w, QWidget):
            lay.addWidget(w)
        else:
            lay.addLayout(w)
    return lay


def copy_text(text: str) -> None:
    QApplication.clipboard().setText(text)


class ElidedLabel(QLabel):
    """Single-line label that elides long text (full text in the tooltip, right-click to copy)."""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._full = ""
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)
        self.set_full_text(text)

    def set_full_text(self, text: str) -> None:
        self._full = text
        self.setToolTip(text if len(text) > 30 else "")
        self._elide()

    def full_text(self) -> str:
        return self._full

    def resizeEvent(self, event: Any) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._elide()

    def _elide(self) -> None:
        width = max(10, self.width() - 2)
        super().setText(self.fontMetrics().elidedText(self._full, Qt.TextElideMode.ElideRight, width))

    def minimumSizeHint(self) -> QSize:
        return QSize(10, self.fontMetrics().height() + 4)

    def sizeHint(self) -> QSize:
        return QSize(self.fontMetrics().horizontalAdvance(self._full) + 4, self.fontMetrics().height() + 4)

    def _menu(self, pos: QPoint) -> None:
        from PySide6.QtWidgets import QMenu

        menu = QMenu(self)
        menu.addAction("Copy", lambda: copy_text(self._full))
        menu.exec(self.mapToGlobal(pos))


class Card(QFrame):
    def __init__(self, title: str = "", parent: QWidget | None = None, margins: int = 14) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(margins, margins, margins, margins)
        self.body.setSpacing(10)
        if title:
            self.body.addWidget(label(title.upper(), "SectionTitle"))


class Banner(QFrame):
    """Inline notice with an accent bar on the left."""

    def __init__(self, text: str, kind: str = "info", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Banner")
        self._kind = kind
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 9, 12, 9)
        lay.setSpacing(10)
        self.icon = QLabel({"info": "i", "warn": "!", "ok": "✓"}.get(kind, "i"))
        self.icon.setFixedSize(20, 20)
        self.icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        color = {"info": theme.current()["accent"], "warn": theme.SEVERITY_COLORS[Severity.MEDIUM],
                 "ok": theme.current()["ok"]}.get(kind, theme.current()["accent"])
        self.icon.setStyleSheet(f"background:{color}; color:white; border-radius:10px; font-weight:800;")
        self.text = label(text, wrap=True)
        self.text.setTextFormat(Qt.TextFormat.RichText)
        self.text.setOpenExternalLinks(False)
        lay.addWidget(self.icon, 0, Qt.AlignmentFlag.AlignTop)
        lay.addWidget(self.text, 1)
        self.actions = QHBoxLayout()
        self.actions.setSpacing(6)
        lay.addLayout(self.actions)

    def set_text(self, text: str) -> None:
        self.text.setText(text)

    def add_action(self, widget: QWidget) -> None:
        self.actions.addWidget(widget)


class Chip(QLabel):
    def __init__(self, text: str = "", color: str = "#8b95a7", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.set_color(color)

    def set_color(self, color: str) -> None:
        c = QColor(color)
        self.setStyleSheet(
            f"QLabel {{ color: {color}; background: rgba({c.red()},{c.green()},{c.blue()},0.13);"
            f" border: 1px solid rgba({c.red()},{c.green()},{c.blue()},0.45); border-radius: 10px;"
            f" padding: 2px 9px; font-weight: 600; font-size: 9pt; }}"
        )


# --------------------------------------------------------------------------- pills in tables


def paint_pill(p: QPainter, rect: QRect, text: str, color: QColor, font: QFont) -> None:
    fm = QFontMetrics(font)
    w = min(rect.width() - 8, fm.horizontalAdvance(text) + 18)
    h = min(rect.height() - 6, fm.height() + 6)
    r = QRectF(rect.left() + 6, rect.center().y() - h / 2 + 1, w, h)
    p.save()
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    bg = QColor(color)
    bg.setAlphaF(0.16)
    border = QColor(color)
    border.setAlphaF(0.5)
    p.setPen(QPen(border, 1))
    p.setBrush(QBrush(bg))
    p.drawRoundedRect(r, h / 2, h / 2)
    p.setPen(color)
    p.setFont(font)
    p.drawText(r, Qt.AlignmentFlag.AlignCenter, text)
    p.restore()


class PillDelegate(QStyledItemDelegate):
    """Draws the cell text as a colored pill when the item carries a COLOR_ROLE."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        color = index.data(COLOR_ROLE)
        if not color:
            super().paint(painter, option, index)
            return
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        text = opt.text
        opt.text = ""
        style = opt.widget.style() if opt.widget else QApplication.style()
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget)
        font = QFont(opt.font)
        font.setPointSizeF(max(7.5, font.pointSizeF() - 1))
        font.setBold(True)
        paint_pill(painter, opt.rect, text, QColor(color), font)

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:
        s = super().sizeHint(option, index)
        return QSize(s.width() + 24, max(s.height(), 30))


# --------------------------------------------------------------------------- verdict gauge


class VerdictGauge(QWidget):
    """Circular score gauge with the verdict label next to it."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.score = 0
        self.level = Severity.INFO
        self.text = "No indicators"
        self.setMinimumSize(250, 84)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    def set_result(self, score: int, level: Severity, text: str) -> None:
        self.score, self.level, self.text = score, level, text
        self.setToolTip(f"Risk score {score}/100: {text}")
        self.update()

    def sizeHint(self) -> QSize:
        return QSize(250, 84)

    def paintEvent(self, _event: Any) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        t = theme.current()
        color = theme.severity_color(self.level)
        if self.level == Severity.INFO:
            color = QColor(t["ok"])
        size = 72
        ring = QRectF(6, (self.height() - size) / 2, size, size)
        track = QPen(QColor(t["surface3"]), 8)
        track.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(track)
        p.drawArc(ring.adjusted(4, 4, -4, -4), 0, 360 * 16)
        arc = QPen(color, 8)
        arc.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(arc)
        span = int(-360 * 16 * max(self.score, 2) / 100)
        p.drawArc(ring.adjusted(4, 4, -4, -4), 90 * 16, span)
        f = QFont(self.font())
        f.setPointSize(17)
        f.setBold(True)
        p.setFont(f)
        p.setPen(QColor(t["text"]))
        p.drawText(ring, Qt.AlignmentFlag.AlignCenter, str(self.score))

        x = ring.right() + 16
        f2 = QFont(self.font())
        f2.setPointSize(8)
        f2.setBold(True)
        f2.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1)
        p.setFont(f2)
        p.setPen(QColor(t["muted"]))
        p.drawText(QRectF(x, ring.top() + 8, self.width() - x, 18), Qt.AlignmentFlag.AlignLeft, "VERDICT")
        f3 = QFont(self.font())
        f3.setPointSize(15)
        f3.setBold(True)
        p.setFont(f3)
        p.setPen(color)
        p.drawText(QRectF(x, ring.top() + 26, self.width() - x, 30), Qt.AlignmentFlag.AlignLeft, self.text)
        f4 = QFont(self.font())
        f4.setPointSize(9)
        p.setFont(f4)
        p.setPen(QColor(t["muted"]))
        p.drawText(QRectF(x, ring.top() + 52, self.width() - x, 18), Qt.AlignmentFlag.AlignLeft,
                   f"Risk score {self.score} / 100")
        p.end()


# --------------------------------------------------------------------------- tables


class _Proxy(QSortFilterProxyModel):
    def __init__(self) -> None:
        super().__init__()
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setFilterKeyColumn(-1)
        self.setSortRole(SORT_ROLE)
        self.extra_filter: Callable[[Any], bool] | None = None

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        if self.extra_filter is not None:
            payload = self.sourceModel().index(row, 0, parent).data(PAYLOAD_ROLE)
            if not self.extra_filter(payload):
                return False
        return super().filterAcceptsRow(row, parent)


class DataTable(QWidget):
    """Table with a filter box, pill-capable cells, sorting and a context menu hook.

    Rows are lists of cells; a cell is either a string or a dict with keys
    text, color (pill), tooltip, sort, mono.
    """

    activated = Signal(object)  # payload of the double-clicked row
    context_menu = Signal(object, QPoint)  # list of selected payloads, global pos
    selection_changed = Signal(object)  # first selected payload (or None)

    def __init__(self, headers: list[str], filter_placeholder: str = "Filter…", show_filter: bool = True,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.headers = headers
        self.model = QStandardItemModel(0, len(headers))
        self.model.setHorizontalHeaderLabels(headers)
        self.proxy = _Proxy()
        self.proxy.setSourceModel(self.model)

        self.view = QTableView()
        self.view.setModel(self.proxy)
        self.view.setItemDelegate(PillDelegate(self.view))
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.view.setAlternatingRowColors(True)
        self.view.setShowGrid(False)
        self.view.setWordWrap(False)
        self.view.setSortingEnabled(True)
        self.view.verticalHeader().setVisible(False)
        self.view.verticalHeader().setDefaultSectionSize(32)
        self.view.horizontalHeader().setHighlightSections(False)
        self.view.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._on_menu)
        self.view.doubleClicked.connect(lambda idx: self.activated.emit(self._payload(idx)))
        self.view.selectionModel().selectionChanged.connect(
            lambda *_: self.selection_changed.emit((self.selected() or [None])[0]))

        self.filter = QLineEdit()
        self.filter.setPlaceholderText(filter_placeholder)
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(self.proxy.setFilterFixedString)
        self.filter.setMaximumWidth(320)
        self.toolbar = QHBoxLayout()
        self.toolbar.setSpacing(8)
        self.toolbar.addWidget(self.filter)
        self.toolbar.addStretch(1)
        self.count_label = label("", "Muted")
        self.toolbar.addWidget(self.count_label)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        if show_filter:
            lay.addLayout(self.toolbar)
        lay.addWidget(self.view, 1)
        self.proxy.rowsInserted.connect(self._update_count)
        self.proxy.rowsRemoved.connect(self._update_count)
        self.proxy.modelReset.connect(self._update_count)
        self.proxy.layoutChanged.connect(self._update_count)

    # ----------------------------------------------------------------- data
    def clear(self) -> None:
        self.model.removeRows(0, self.model.rowCount())
        self._update_count()

    def _make_item(self, cell: Any) -> QStandardItem:
        if isinstance(cell, dict):
            text = str(cell.get("text", ""))
            item = QStandardItem(text)
            if cell.get("color"):
                item.setData(cell["color"], COLOR_ROLE)
            if cell.get("fg"):
                item.setForeground(QColor(cell["fg"]))
            if cell.get("bold"):
                f = item.font()
                f.setBold(True)
                item.setFont(f)
            if cell.get("mono"):
                item.setFont(theme.mono_font(9))
            item.setToolTip(str(cell.get("tooltip", text)))
            item.setData(cell.get("sort", text), SORT_ROLE)
        else:
            text = "" if cell is None else str(cell)
            item = QStandardItem(text)
            item.setToolTip(text if len(text) > 40 else "")
            item.setData(text.lower(), SORT_ROLE)
        item.setEditable(False)
        return item

    def add_row(self, cells: list[Any], payload: Any = None) -> None:
        items = [self._make_item(c) for c in cells]
        items[0].setData(payload, PAYLOAD_ROLE)
        self.model.appendRow(items)

    def set_rows(self, rows: list[tuple[list[Any], Any]]) -> None:
        self.view.setSortingEnabled(False)
        self.clear()
        for cells, payload in rows:
            self.add_row(cells, payload)
        self.view.setSortingEnabled(True)
        self._update_count()

    def set_column_widths(self, widths: dict[int, int]) -> None:
        for col, w in widths.items():
            self.view.setColumnWidth(col, w)

    def stretch(self, col: int) -> None:
        self.view.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.Stretch)
        self.view.horizontalHeader().setStretchLastSection(False)

    def refilter(self) -> None:
        self.proxy.invalidate()
        self._update_count()

    # ----------------------------------------------------------------- selection
    def _payload(self, proxy_index: QModelIndex) -> Any:
        src = self.proxy.mapToSource(proxy_index)
        return self.model.index(src.row(), 0).data(PAYLOAD_ROLE)

    def selected(self) -> list[Any]:
        rows = sorted({i.row() for i in self.view.selectionModel().selectedRows()})
        return [self._payload(self.proxy.index(r, 0)) for r in rows]

    def all_payloads(self, visible_only: bool = True) -> list[Any]:
        if visible_only:
            return [self._payload(self.proxy.index(r, 0)) for r in range(self.proxy.rowCount())]
        return [self.model.index(r, 0).data(PAYLOAD_ROLE) for r in range(self.model.rowCount())]

    def _on_menu(self, pos: QPoint) -> None:
        idx = self.view.indexAt(pos)
        if not idx.isValid():
            return
        if not self.view.selectionModel().isRowSelected(idx.row(), idx.parent()):
            self.view.selectRow(idx.row())
        self.context_menu.emit(self.selected(), self.view.viewport().mapToGlobal(pos))

    def _update_count(self, *_: Any) -> None:
        total = self.model.rowCount()
        shown = self.proxy.rowCount()
        self.count_label.setText(f"{shown} of {total}" if shown != total else f"{total} item{'s' if total != 1 else ''}")

    def add_tool(self, widget: QWidget) -> None:
        self.toolbar.insertWidget(self.toolbar.count() - 2, widget)


def severity_cell(sev: Severity) -> dict:
    return {"text": sev.label, "color": theme.SEVERITY_COLORS[sev], "sort": int(sev)}


def toggle(text: str, checked: bool = False, slot: Callable | None = None) -> QCheckBox:
    cb = QCheckBox(text)
    cb.setChecked(checked)
    cb.setCursor(Qt.CursorShape.PointingHandCursor)
    if slot is not None:
        cb.toggled.connect(slot)
    return cb


# --------------------------------------------------------------------------- drop zone


class DropZone(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setMinimumHeight(220)

    def set_hover(self, on: bool) -> None:
        self.setProperty("hover", on)
        self.style().unpolish(self)
        self.style().polish(self)


# --------------------------------------------------------------------------- icon


def app_icon() -> QIcon:
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(size, size)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = float(size)
        path = QPainterPath()
        path.addRoundedRect(QRectF(0, 0, s, s), s * 0.22, s * 0.22)
        p.fillPath(path, QColor("#2f6fe4"))
        pen = QPen(QColor("white"), max(1.2, s * 0.07))
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        env = QRectF(s * 0.2, s * 0.3, s * 0.6, s * 0.42)
        p.drawRoundedRect(env, s * 0.05, s * 0.05)
        flap = QPainterPath()
        flap.moveTo(env.left(), env.top())
        flap.lineTo(env.center().x(), env.top() + env.height() * 0.55)
        flap.lineTo(env.right(), env.top())
        p.drawPath(flap)
        p.setBrush(QColor("#ff5d5d"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QRectF(s * 0.66, s * 0.16, s * 0.22, s * 0.22))
        p.end()
        icon.addPixmap(pm)
    return icon
