from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDockWidget, QMainWindow

from nids.core.ml_settings import MlSettings
from nids.core.response_settings import ResponseSettings
from nids.response.block import add_block_rule, remove_block_rule
from nids.response.manager import BlockManager
from nids.storage.event_store import EventStore
from nids.ui.theme import DARK_STYLESHEET
from nids.ui.widgets.dashboard_panel import DashboardPanel
from nids.ui.widgets.logs_panel import LogsPanel
from nids.ui.widgets.ml_panel import MlPanel
from nids.ui.widgets.response_panel import ResponsePanel
from nids.ui.widgets.signatures_panel import SignaturesPanel
from nids.ui.widgets.traffic_panel import TrafficPanel


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("NIDS")
        self.resize(1300, 800)
        self.setStyleSheet(DARK_STYLESHEET)
        self.setDockNestingEnabled(True)

        self._block_manager = BlockManager(add_rule=add_block_rule, remove_rule=remove_block_rule)
        self._event_store = EventStore()
        self._signatures_panel = SignaturesPanel()
        self._traffic_panel = TrafficPanel()
        self._logs_panel = LogsPanel(self._event_store)
        self._ml_settings = MlSettings()
        self._response_settings = ResponseSettings()

        # zona centrala, ca "Scene" in Unity - vederea principala de lucru
        self._dashboard = DashboardPanel(
            self._block_manager,
            self._event_store,
            self._signatures_panel,
            self._traffic_panel,
            self._logs_panel,
            self._ml_settings,
            self._response_settings,
        )
        self.setCentralWidget(self._dashboard)

        # latime minima ca sa incapa toate etichetele din tab-bar-ul
        # andocat, altfel Qt il micsoreaza sub necesar la fiecare toggle
        # de vizibilitate si apar sageti de overflow + text taiat cu "..."
        right_dock_min_width = 260

        self._docks: dict[str, QDockWidget] = {}
        self._add_dock(
            "Semnaturi",
            self._signatures_panel,
            Qt.DockWidgetArea.RightDockWidgetArea,
            min_width=right_dock_min_width,
        )
        self._add_dock(
            "ML",
            MlPanel(self._dashboard, self._ml_settings),
            Qt.DockWidgetArea.RightDockWidgetArea,
            tabify_with="Semnaturi",
            min_width=right_dock_min_width,
        )
        self._add_dock(
            "Raspuns",
            ResponsePanel(self._block_manager, self._response_settings),
            Qt.DockWidgetArea.RightDockWidgetArea,
            tabify_with="Semnaturi",
            min_width=right_dock_min_width,
        )
        self._add_dock(
            "Loguri",
            self._logs_panel,
            Qt.DockWidgetArea.BottomDockWidgetArea,
            min_height=120,
        )
        self._add_dock(
            "Trafic",
            self._traffic_panel,
            Qt.DockWidgetArea.BottomDockWidgetArea,
            tabify_with="Loguri",
            min_height=120,
        )
        self._docks["Semnaturi"].raise_()
        self._docks["Loguri"].raise_()

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
        self._dashboard.shutdown()
        # opreste timer-ul de refresh al LogsPanel INAINTE de a inchide
        # EventStore - altfel un refresh programat mai poate ruleaza dupa
        # close() si loveste o conexiune SQLite inchisa (bug real gasit
        # de user: sqlite3.ProgrammingError: Cannot operate on a closed database)
        self._logs_panel.stop()
        self._block_manager.shutdown()
        self._event_store.close()
        super().closeEvent(event)
