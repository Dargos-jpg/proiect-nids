# tema dark, paleta inspirata din VS Code Dark+

DARK_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #1e1e1e;
    color: #cccccc;
    font-size: 13px;
}

QMenuBar {
    background-color: #2d2d2d;
    border-bottom: 1px solid #3c3c3c;
}
QMenuBar::item:selected {
    background-color: #094771;
}
QMenu {
    background-color: #252526;
    border: 1px solid #3c3c3c;
}
QMenu::item:selected {
    background-color: #094771;
}

QStatusBar {
    background-color: #007acc;
    color: #ffffff;
}

QDockWidget {
    color: #cccccc;
}
QDockWidget::title {
    background-color: #2d2d2d;
    padding: 6px 8px;
    border-bottom: 1px solid #3c3c3c;
}

QTabBar::tab {
    background-color: #2d2d2d;
    color: #8a8a8a;
    padding: 6px 14px;
    border: 1px solid #3c3c3c;
    border-bottom: none;
}
QTabBar::tab:selected {
    background-color: #1e1e1e;
    color: #ffffff;
    border-bottom: 2px solid #007acc;
}
QTabBar::tab:hover {
    background-color: #333333;
}

QPushButton {
    background-color: #0e639c;
    color: #ffffff;
    border: none;
    padding: 6px 14px;
    border-radius: 3px;
}
QPushButton:hover {
    background-color: #1177bb;
}
QPushButton:pressed {
    background-color: #0d5a8f;
}

QScrollBar:vertical {
    background: #1e1e1e;
    width: 12px;
}
QScrollBar::handle:vertical {
    background: #3c3c3c;
    min-height: 20px;
    border-radius: 5px;
}
QScrollBar::handle:vertical:hover {
    background: #4c4c4c;
}

QSplitter::handle {
    background-color: #3c3c3c;
}

QListWidget {
    background-color: #1e1e1e;
    border: 1px solid #3c3c3c;
    outline: none;
}
QListWidget::item {
    padding: 4px 6px;
}
QListWidget::item:selected {
    background-color: #094771;
}

QTableWidget {
    background-color: #1e1e1e;
    border: 1px solid #3c3c3c;
    gridline-color: #3c3c3c;
    outline: none;
}
QTableWidget::item {
    padding: 4px 6px;
}
QTableWidget::item:selected {
    background-color: #094771;
}
QHeaderView::section {
    background-color: #2d2d2d;
    color: #cccccc;
    padding: 4px 6px;
    border: 1px solid #3c3c3c;
}

QSlider::groove:horizontal {
    background: #3c3c3c;
    height: 4px;
    border-radius: 2px;
}
QSlider::handle:horizontal {
    background: #007acc;
    width: 14px;
    margin: -6px 0;
    border-radius: 7px;
}
QSlider::handle:horizontal:hover {
    background: #1177bb;
}
"""
