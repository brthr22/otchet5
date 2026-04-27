"""
Main GUI application for RedCheck Protocol Generator.
Built with PySide6.
"""

import sys
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QLabel, QPushButton, QFileDialog, QSpinBox,
    QScrollArea, QFormLayout, QLineEdit, QProgressBar, QTextEdit,
    QMessageBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QFrame
)
from PySide6.QtCore import Qt, Signal, QObject, QThread
from PySide6.QtGui import QFont, QColor, QIcon

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import Host, PortScan, Vulnerability, ScanMetadata
from parsers.inventory_parser import InventoryParser
from parsers.pentest_parser import PentestParser
from parsers.vulnerability_parser import VulnerabilityParser
from doc_generator import DocumentGenerator


logger = logging.getLogger(__name__)


@dataclass
class HostFiles:
    """Container for the three report files for a single host."""
    inventory_path: Path = None
    pentest_path: Path = None
    vulns_path: Path = None


@dataclass
class ParsedHostData:
    """Container for parsed data for a single host."""
    host: Optional[Host] = None
    port_scan: Optional[PortScan] = None
    vulnerabilities: List[Vulnerability] = None
    scan_metadata: Optional[ScanMetadata] = None
    errors: List[str] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.errors is None:
            self.errors = []


class ParseWorker(QObject):
    """Background worker for parsing files."""
    progress = Signal(int, str)  # host_index, message
    host_parsed = Signal(int, ParsedHostData)  # host_index, data
    finished = Signal()
    error = Signal(str)
    
    def __init__(self, host_files: List[HostFiles], output_dir: Path):
        super().__init__()
        self.host_files = host_files
        self.output_dir = output_dir
    
    def run(self):
        """Parse all host files."""
        try:
            for i, files in enumerate(self.host_files):
                self.progress.emit(i, "Начало обработки...")
                
                data = ParsedHostData()
                
                # Parse inventory
                if files.inventory_path and files.inventory_path.exists():
                    try:
                        self.progress.emit(i, f"Парсинг инвентаризации: {files.inventory_path.name}")
                        parser = InventoryParser()
                        hosts = parser.parse(files.inventory_path)
                        if hosts:
                            data.host = hosts[0]  # Take first host
                            logger.info(f"Parsed inventory for host {i}: {data.host.hostname or data.host.ip}")
                    except Exception as e:
                        msg = f"Ошибка парсинга инвентаризации: {e}"
                        logger.error(msg)
                        data.errors.append(msg)
                
                # Parse pentest
                if files.pentest_path and files.pentest_path.exists():
                    try:
                        self.progress.emit(i, f"Парсинг пентеста: {files.pentest_path.name}")
                        parser = PentestParser()
                        scans = parser.parse(files.pentest_path)
                        if scans:
                            data.port_scan = scans[0]  # Take first scan
                            logger.info(f"Parsed pentest for host {i}: {len(data.port_scan.open_ports)} ports")
                    except Exception as e:
                        msg = f"Ошибка парсинга пентеста: {e}"
                        logger.error(msg)
                        data.errors.append(msg)
                
                # Parse vulnerabilities
                if files.vulns_path and files.vulns_path.exists():
                    try:
                        self.progress.emit(i, f"Парсинг уязвимостей: {files.vulns_path.name}")
                        parser = VulnerabilityParser()
                        vulns, metadata = parser.parse(files.vulns_path)
                        data.vulnerabilities = vulns
                        data.scan_metadata = metadata
                        logger.info(f"Parsed vulnerabilities for host {i}: {len(vulns)} vulns")
                    except Exception as e:
                        msg = f"Ошибка парсинга уязвимостей: {e}"
                        logger.error(msg)
                        data.errors.append(msg)
                
                self.host_parsed.emit(i, data)
            
            self.finished.emit()
            
        except Exception as e:
            self.error.emit(str(e))
            logger.exception("Worker error")


class HostFileWidget(QWidget):
    """Widget for selecting files for a single host."""
    
    files_changed = Signal()  # Emitted when files are changed
    
    def __init__(self, host_number: int, parent=None):
        super().__init__(parent)
        self.host_number = host_number
        self.files = HostFiles()
        
        self._init_ui()
    
    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(5)
        
        # Title
        title = QLabel(f"<b>Хост #{self.host_number}</b>")
        title.setStyleSheet("font-size: 14px; color: #2196F3;")
        layout.addWidget(title)
        
        # File selectors
        form = QFormLayout()
        form.setSpacing(5)
        
        # Inventory file
        self.inv_btn = QPushButton("Выбрать файл...")
        self.inv_btn.clicked.connect(lambda: self._select_file('inventory'))
        self.inv_label = QLabel("Не выбран")
        self.inv_label.setStyleSheet("color: gray; font-style: italic;")
        
        inv_layout = QHBoxLayout()
        inv_layout.addWidget(self.inv_btn)
        inv_layout.addWidget(self.inv_label, 1)
        form.addRow("Инвентаризация:", inv_layout)
        
        # Pentest file
        self.pentest_btn = QPushButton("Выбрать файл...")
        self.pentest_btn.clicked.connect(lambda: self._select_file('pentest'))
        self.pentest_label = QLabel("Не выбран")
        self.pentest_label.setStyleSheet("color: gray; font-style: italic;")
        
        pentest_layout = QHBoxLayout()
        pentest_layout.addWidget(self.pentest_btn)
        pentest_layout.addWidget(self.pentest_label, 1)
        form.addRow("Пентест:", pentest_layout)
        
        # Vulnerabilities file
        self.vulns_btn = QPushButton("Выбрать файл...")
        self.vulns_btn.clicked.connect(lambda: self._select_file('vulns'))
        self.vulns_label = QLabel("Не выбран")
        self.vulns_label.setStyleSheet("color: gray; font-style: italic;")
        
        vulns_layout = QHBoxLayout()
        vulns_layout.addWidget(self.vulns_btn)
        vulns_layout.addWidget(self.vulns_label, 1)
        form.addRow("Уязвимости:", vulns_layout)
        
        layout.addLayout(form)
        
        # Separator
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        layout.addWidget(line)
    
    def _select_file(self, file_type: str):
        """Open file dialog and select file."""
        filters = {
            'inventory': "XML файлы (*.xml);;Все файлы (*)",
            'pentest': "XML/TXT файлы (*.xml *.txt);;Все файлы (*)",
            'vulns': "XML файлы (*.xml);;Все файлы (*)"
        }
        
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            f"Выберите файл для {'инвентаризации' if file_type == 'inventory' else 'пентеста' if file_type == 'pentest' else 'уязвимостей'}",
            "",
            filters[file_type]
        )
        
        if file_path:
            path = Path(file_path)
            if file_type == 'inventory':
                self.files.inventory_path = path
                self.inv_label.setText(path.name)
                self.inv_label.setStyleSheet("color: green;")
            elif file_type == 'pentest':
                self.files.pentest_path = path
                self.pentest_label.setText(path.name)
                self.pentest_label.setStyleSheet("color: green;")
            elif file_type == 'vulns':
                self.files.vulns_path = path
                self.vulns_label.setText(path.name)
                self.vulns_label.setStyleSheet("color: green;")
            
            self.files_changed.emit()
    
    def get_files(self) -> HostFiles:
        """Get current file paths."""
        return self.files
    
    def set_status(self, status: str):
        """Update status display."""
        pass  # Can be extended to show parsing status


class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self):
        super().__init__()
        
        self.host_widgets: List[HostFileWidget] = []
        self.host_data: Dict[int, ParsedHostData] = {}
        self.template_path: Optional[Path] = None
        self.output_path: Optional[Path] = None
        
        self.worker: Optional[ParseWorker] = None
        self.worker_thread: Optional[QThread] = None
        
        self._init_ui()
        self._setup_logging()
    
    def _init_ui(self):
        """Initialize user interface."""
        self.setWindowTitle("RedCheck Protocol Generator")
        self.setMinimumSize(900, 700)
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(10)
        
        # Header
        header = QLabel("<h1>Генератор протокола информационной безопасности</h1>")
        header.setStyleSheet("color: #1976D2; padding: 10px;")
        main_layout.addWidget(header)
        
        # Create splitter for resizable panes
        splitter = QSplitter(Qt.Vertical)
        main_layout.addWidget(splitter, 1)
        
        # Top pane: Configuration
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        splitter.addWidget(top_widget)
        
        # Number of hosts
        num_hosts_group = QGroupBox("Количество хостов")
        num_hosts_layout = QHBoxLayout(num_hosts_group)
        
        self.num_hosts_spin = QSpinBox()
        self.num_hosts_spin.setRange(1, 100)
        self.num_hosts_spin.setValue(1)
        self.num_hosts_spin.valueChanged.connect(self._on_num_hosts_changed)
        
        num_hosts_layout.addWidget(QLabel("Количество хостов:"))
        num_hosts_layout.addWidget(self.num_hosts_spin)
        num_hosts_layout.addStretch()
        
        top_layout.addWidget(num_hosts_group)
        
        # Host files container with scroll
        files_group = QGroupBox("Файлы отчетов")
        files_layout = QVBoxLayout(files_group)
        
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        
        self.hosts_container = QWidget()
        self.hosts_layout = QVBoxLayout(self.hosts_container)
        self.hosts_layout.setSpacing(10)
        
        self.scroll.setWidget(self.hosts_container)
        files_layout.addWidget(self.scroll)
        
        top_layout.addWidget(files_group)
        
        # Template selection
        template_group = QGroupBox("Шаблон документа")
        template_layout = QHBoxLayout(template_group)
        
        self.template_label = QLabel("Шаблон не выбран")
        self.template_label.setStyleSheet("color: gray; font-style: italic;")
        
        self.template_btn = QPushButton("Выбрать шаблон DOCX...")
        self.template_btn.clicked.connect(self._select_template)
        
        template_layout.addWidget(self.template_btn)
        template_layout.addWidget(self.template_label, 1)
        
        top_layout.addWidget(template_group)
        
        # Bottom pane: Progress and results
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        splitter.addWidget(bottom_widget)
        
        # Progress
        progress_group = QGroupBox("Прогресс")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        self.status_label = QLabel("Готов к работе")
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        
        bottom_layout.addWidget(progress_group)
        
        # Log output
        log_group = QGroupBox("Журнал операций")
        log_layout = QVBoxLayout(log_group)
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(150)
        self.log_output.setFont(QFont("Consolas", 9))
        
        log_layout.addWidget(self.log_output)
        
        bottom_layout.addWidget(log_group)
        
        # Action buttons
        buttons_layout = QHBoxLayout()
        
        self.generate_btn = QPushButton("Сгенерировать протокол")
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.generate_btn.clicked.connect(self._generate_protocol)
        
        self.clear_btn = QPushButton("Очистить")
        self.clear_btn.clicked.connect(self._clear_all)
        
        buttons_layout.addWidget(self.generate_btn)
        buttons_layout.addWidget(self.clear_btn)
        buttons_layout.addStretch()
        
        bottom_layout.addLayout(buttons_layout)
        
        # Initialize with one host
        self._update_host_widgets()
    
    def _setup_logging(self):
        """Setup logging to UI."""
        class UILogHandler(logging.Handler):
            def __init__(self, callback):
                super().__init__()
                self.callback = callback
            
            def emit(self, record):
                msg = self.format(record)
                self.callback(msg)
        
        handler = UILogHandler(self._add_log)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(handler)
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)
    
    def _add_log(self, message: str):
        """Add message to log output."""
        self.log_output.append(message)
        self.log_output.verticalScrollBar().setValue(
            self.log_output.verticalScrollBar().maximum()
        )
    
    def _on_num_hosts_changed(self, value: int):
        """Handle change in number of hosts."""
        self._update_host_widgets()
    
    def _update_host_widgets(self):
        """Update host file widgets based on count."""
        count = self.num_hosts_spin.value()
        current_count = len(self.host_widgets)
        
        if count > current_count:
            # Add widgets
            for i in range(current_count, count):
                widget = HostFileWidget(i + 1)
                widget.files_changed.connect(self._check_ready)
                self.host_widgets.append(widget)
                self.hosts_layout.addWidget(widget)
        elif count < current_count:
            # Remove widgets
            for i in range(current_count - 1, count - 1, -1):
                widget = self.host_widgets.pop(i)
                self.hosts_layout.removeWidget(widget)
                widget.deleteLater()
        
        self._check_ready()
    
    def _select_template(self):
        """Select DOCX template file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите шаблон DOCX",
            "",
            "DOCX файлы (*.docx);;Все файлы (*)"
        )
        
        if file_path:
            self.template_path = Path(file_path)
            self.template_label.setText(self.template_path.name)
            self.template_label.setStyleSheet("color: green;")
            self._log(f"Шаблон выбран: {self.template_path}")
    
    def _check_ready(self):
        """Check if ready to generate."""
        # Check if template is selected
        has_template = self.template_path is not None
        
        # Check if at least one host has files
        has_files = any(
            w.files.inventory_path or w.files.pentest_path or w.files.vulns_path
            for w in self.host_widgets
        )
        
        self.generate_btn.setEnabled(has_template and has_files)
    
    def _generate_protocol(self):
        """Start protocol generation."""
        if not self.template_path:
            QMessageBox.warning(self, "Ошибка", "Выберите шаблон документа!")
            return
        
        # Collect host files
        host_files = [w.get_files() for w in self.host_widgets]
        
        # Ask for output location
        default_name = f"protocol_{len(host_files)}_hosts.docx"
        output_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить протокол",
            default_name,
            "DOCX файлы (*.docx)"
        )
        
        if not output_path:
            return
        
        self.output_path = Path(output_path)
        
        # Disable UI during processing
        self._set_ui_enabled(False)
        self.status_label.setText("Обработка...")
        self.progress_bar.setValue(0)
        
        # Start worker thread
        self.worker_thread = QThread()
        self.worker = ParseWorker(host_files, self.output_path.parent)
        self.worker.moveToThread(self.worker_thread)
        
        # Connect signals
        self.worker.progress.connect(self._on_parse_progress)
        self.worker.host_parsed.connect(self._on_host_parsed)
        self.worker.finished.connect(self._on_parse_finished)
        self.worker.error.connect(self._on_parse_error)
        
        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)
        
        self.worker_thread.start()
    
    def _on_parse_progress(self, host_index: int, message: str):
        """Handle parse progress update."""
        total = len(self.host_widgets) * 3  # 3 files per host
        current = host_index * 3
        progress = int((current / total) * 100)
        self.progress_bar.setValue(progress)
        self.status_label.setText(f"Хост {host_index + 1}: {message}")
        self._log(message)
    
    def _on_host_parsed(self, host_index: int, data: ParsedHostData):
        """Handle host parsed event."""
        self.host_data[host_index] = data
        
        # Update status
        status_parts = []
        if data.host:
            status_parts.append(f"✓ Инвентаризация: {data.host.hostname or data.host.ip}")
        if data.port_scan:
            status_parts.append(f"✓ Порты: {len(data.port_scan.open_ports)}")
        if data.vulnerabilities:
            status_parts.append(f"✓ Уязвимости: {len(data.vulnerabilities)}")
        if data.errors:
            status_parts.append(f"⚠ Ошибок: {len(data.errors)}")
        
        self._log(f"Хост {host_index + 1}: {', '.join(status_parts)}")
    
    def _on_parse_finished(self):
        """Handle parse completion."""
        self.progress_bar.setValue(100)
        self.status_label.setText("Генерация документа...")
        self._log("Парсинг завершен, генерация документа...")
        
        try:
            # Generate document
            generator = DocumentGenerator(self.template_path)
            
            # Prepare data for generator
            hosts_data = []
            for i in range(len(self.host_widgets)):
                data = self.host_data.get(i, ParsedHostData())
                hosts_data.append({
                    'host': data.host,
                    'port_scan': data.port_scan,
                    'vulnerabilities': data.vulnerabilities,
                    'scan_metadata': data.scan_metadata,
                    'errors': data.errors
                })
            
            # Generate
            generator.generate(self.output_path, hosts_data)
            
            self.status_label.setText(f"Готово! Сохранено в {self.output_path}")
            self._log(f"Документ сохранен: {self.output_path}")
            
            QMessageBox.information(
                self,
                "Успех",
                f"Протокол успешно сгенерирован!\n\n{self.output_path}"
            )
            
        except Exception as e:
            self._log(f"Ошибка генерации: {e}")
            logger.exception("Generation error")
            QMessageBox.critical(self, "Ошибка", f"Ошибка генерации: {e}")
        
        finally:
            self._set_ui_enabled(True)
    
    def _on_parse_error(self, error_msg: str):
        """Handle parse error."""
        self._log(f"Критическая ошибка: {error_msg}")
        QMessageBox.critical(self, "Ошибка", f"Ошибка обработки: {error_msg}")
        self._set_ui_enabled(True)
    
    def _set_ui_enabled(self, enabled: bool):
        """Enable/disable UI elements."""
        self.num_hosts_spin.setEnabled(enabled)
        self.template_btn.setEnabled(enabled)
        self.generate_btn.setEnabled(enabled and self.template_path is not None)
        self.clear_btn.setEnabled(enabled)
        
        for widget in self.host_widgets:
            widget.setEnabled(enabled)
    
    def _clear_all(self):
        """Clear all selections."""
        self.num_hosts_spin.setValue(1)
        self.template_path = None
        self.template_label.setText("Шаблон не выбран")
        self.template_label.setStyleSheet("color: gray; font-style: italic;")
        self.host_data.clear()
        self.log_output.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Готов к работе")
        self._log("Все данные очищены")
    
    def _log(self, message: str):
        """Log message to UI."""
        self._add_log(message)


def run_gui():
    """Run the GUI application."""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Set application-wide font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    run_gui()
