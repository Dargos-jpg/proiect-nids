from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDockWidget, QMainWindow

from nids.ui.theme import DARK_STYLESHEET
from nids.ui.widgets.common import placeholder_widget
from nids.ui.widgets.dashboard_panel import DashboardPanel


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("NIDS")
        self.resize(1300, 800)
        self.setStyleSheet(DARK_STYLESHEET)
        self.setDockNestingEnabled(True)

        # zona centrala, ca "Scene" in Unity - vederea principala de lucru
        self._dashboard = DashboardPanel()
        self.setCentralWidget(self._dashboard)

        # latime minima ca sa incapa toate etichetele din tab-bar-ul
        # andocat, altfel Qt il micsoreaza sub necesar la fiecare toggle
        # de vizibilitate si apar sageti de overflow + text taiat cu "..."
        right_dock_min_width = 260

        self._docks: dict[str, QDockWidget] = {}
        self._add_dock(
            "Semnaturi",
            placeholder_widget("semnaturi - in lucru"),
            Qt.DockWidgetArea.RightDockWidgetArea,
            min_width=right_dock_min_width,
        )
        self._add_dock(
            "ML",
            placeholder_widget("ML - in lucru"),
            Qt.DockWidgetArea.RightDockWidgetArea,
            tabify_with="Semnaturi",
            min_width=right_dock_min_width,
        )
        self._add_dock(
            "Raspuns",
            placeholder_widget("raspuns - in lucru"),
            Qt.DockWidgetArea.RightDockWidgetArea,
            tabify_with="Semnaturi",
            min_width=right_dock_min_width,
        )
        self._add_dock(
            "Loguri",
            placeholder_widget("loguri - in lucru"),
            Qt.DockWidgetArea.BottomDockWidgetArea,
            min_height=120,
        )
        self._docks["Semnaturi"].raise_()

        self.resizeDocks(
            [self._docks["Semnaturi"]], [320], Qt.Orientation.Horizontal
        )
        self.resizeDocks(
            [self._docks["Loguri"]], [180], Qt.Orientation.Vertical
        )

        self._build_view_menu()
        self.statusBar().showMessage("pregatit")

    def _add_dock(
        self,
        title: str,
        widget,
        area: Qt.DockWidgetArea,
        tabify_with: str | None = None,
        min_width: int | None = None,
        min_height: int | None = None,
    ) -> QDockWidget:
        dock = QDockWidget(title, self)
        dock.setObjectName(f"dock_{title}")
        dock.setWidget(widget)
        if min_width is not None:
            dock.setMinimumWidth(min_width)
        if min_height is not None:
            dock.setMinimumHeight(min_height)
        if tabify_with and tabify_with in self._docks:
            self.tabifyDockWidget(self._docks[tabify_with], dock)
        else:
            self.addDockWidget(area, dock)
        self._docks[title] = dock
        return dock

    def _build_view_menu(self) -> None:
        view_menu = self.menuBar().addMenu("Vizualizare")
        for dock in self._docks.values():
            action = dock.toggleViewAction()
            action.toggled.connect(lambda _checked: self.statusBar().showMessage("pregatit"))
            view_menu.addAction(action)

    def closeEvent(self, event) -> None:  # noqa: N802 - override Qt
        self._dashboard.stop_monitoring()
        super().closeEvent(event)
