from PySide6.QtWidgets import QApplication

from nids.response.manager import BlockManager
from nids.ui.widgets.response_panel import ResponsePanel


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _fake_block_manager() -> BlockManager:
    return BlockManager(add_rule=lambda ip: None, remove_rule=lambda ip: None)


def test_response_panel_shows_active_blocks():
    _app()
    manager = _fake_block_manager()
    manager.block("10.0.0.9", reason="port scan")

    panel = ResponsePanel(manager)

    assert panel._table.rowCount() == 1
    assert panel._table.item(0, 0).text() == "10.0.0.9"
    assert panel._table.item(0, 1).text() == "port scan"


def test_response_panel_unblock_selected_row():
    _app()
    manager = _fake_block_manager()
    manager.block("10.0.0.9", reason="port scan")

    panel = ResponsePanel(manager)
    panel._table.selectRow(0)
    panel._on_unblock_clicked()

    assert not manager.is_blocked("10.0.0.9")
    assert panel._table.rowCount() == 0


def test_response_panel_refreshes_when_blocks_change():
    _app()
    manager = _fake_block_manager()
    panel = ResponsePanel(manager)
    assert panel._table.rowCount() == 0

    manager.block("10.0.0.9", reason="port scan")
    panel._refresh()

    assert panel._table.rowCount() == 1


def test_response_panel_shows_active_block_in_history_as_active():
    _app()
    manager = _fake_block_manager()
    manager.block("10.0.0.9", reason="port scan")

    panel = ResponsePanel(manager)

    assert panel._history_table.rowCount() == 1
    assert panel._history_table.item(0, 0).text() == "10.0.0.9"
    assert panel._history_table.item(0, 3).text() == "-"
    assert panel._history_table.item(0, 4).text() == "activa"


def test_response_panel_history_survives_unblock():
    """regresie: fara istoric, o blocare ridicata (manual sau expirata)
    disparea complet - userul nu mai avea nicio urma ca s-a intamplat"""
    _app()
    manager = _fake_block_manager()
    manager.block("10.0.0.9", reason="port scan")
    panel = ResponsePanel(manager)

    panel._table.selectRow(0)
    panel._on_unblock_clicked()

    assert panel._table.rowCount() == 0
    assert panel._history_table.rowCount() == 1
    assert panel._history_table.item(0, 4).text() == "manual"
    assert panel._history_table.item(0, 3).text() != "-"


def test_response_panel_history_shows_most_recent_first():
    _app()
    manager = _fake_block_manager()
    manager.block("10.0.0.1", reason="primul")
    manager.block("10.0.0.2", reason="al doilea")

    panel = ResponsePanel(manager)

    assert panel._history_table.item(0, 0).text() == "10.0.0.2"
    assert panel._history_table.item(1, 0).text() == "10.0.0.1"
