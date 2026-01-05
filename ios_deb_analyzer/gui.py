"""GUI interface module using PyQt6.

This module provides a graphical user interface for iOS Deb Analyzer.
"""

import sys
import tempfile
import json
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTreeWidget, QTreeWidgetItem,
    QTabWidget, QTextEdit, QSplitter, QMessageBox, QProgressBar,
    QGroupBox, QScrollArea, QFrame, QStatusBar, QDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QDragEnterEvent, QDropEvent, QSyntaxHighlighter, QTextCharFormat

try:
    from .deb_parser import DebParser
    from .dylib_analyzer import DylibAnalyzer
    from .models import DebContents, DylibAnalysis, InvalidDebError, InvalidMachOError
    from .report_generator import ReportGenerator
except ImportError:
    from ios_deb_analyzer.deb_parser import DebParser
    from ios_deb_analyzer.dylib_analyzer import DylibAnalyzer
    from ios_deb_analyzer.models import DebContents, DylibAnalysis, InvalidDebError, InvalidMachOError
    from ios_deb_analyzer.report_generator import ReportGenerator


class AnalyzerThread(QThread):
    """Background thread for file analysis."""
    finished = pyqtSignal(object, object)  # deb_contents, dylib_analysis
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, file_path: Path, dylib_only: bool = False):
        super().__init__()
        self.file_path = file_path
        self.dylib_only = dylib_only

    def run(self):
        try:
            deb_parser = DebParser()
            dylib_analyzer = DylibAnalyzer()
            
            deb_contents: Optional[DebContents] = None
            dylib_analysis: Optional[DylibAnalysis] = None

            if self.dylib_only:
                self.progress.emit("Analyzing dylib...")
                dylib_analysis = dylib_analyzer.analyze(self.file_path)
            else:
                self.progress.emit("Parsing deb package...")
                deb_contents = deb_parser.parse(self.file_path)
                
                if deb_contents.dylib_paths:
                    self.progress.emit("Extracting and analyzing dylib...")
                    with tempfile.TemporaryDirectory() as temp_dir:
                        extract_path = deb_parser.extract_to(self.file_path, Path(temp_dir))
                        
                        for dylib_path in deb_contents.dylib_paths:
                            full_dylib_path = extract_path / dylib_path
                            if full_dylib_path.exists():
                                dylib_analysis = dylib_analyzer.analyze(full_dylib_path)
                                break

            self.finished.emit(deb_contents, dylib_analysis)
        except (InvalidDebError, InvalidMachOError, FileNotFoundError) as e:
            self.error.emit(str(e))
        except Exception as e:
            self.error.emit(f"Unexpected error: {e}")


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.deb_contents: Optional[DebContents] = None
        self.dylib_analysis: Optional[DylibAnalysis] = None
        self.current_file: Optional[Path] = None
        self.dylib_path: Optional[Path] = None  # Path to extracted dylib
        self.analyzer_thread: Optional[AnalyzerThread] = None
        self.lief_binary = None  # LIEF binary for disassembly
        
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("iOS Deb Analyzer")
        self.setMinimumSize(1000, 700)
        self.setAcceptDrops(True)

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

        # Top bar - file selection
        top_bar = self.create_top_bar()
        layout.addWidget(top_bar)

        # Main content area with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Package info
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Tabs for detailed info
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([350, 650])
        layout.addWidget(splitter, 1)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Drag & drop a .deb or .dylib file, or click 'Open File'")

        # Progress bar (hidden by default)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.hide()
        self.status_bar.addPermanentWidget(self.progress_bar)

    def create_top_bar(self) -> QWidget:
        """Create the top bar with file selection controls."""
        frame = QFrame()
        frame.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(10, 10, 10, 10)

        # File path label
        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(self.file_label, 1)

        # Open file button
        self.open_btn = QPushButton("Open File")
        self.open_btn.setMinimumWidth(100)
        self.open_btn.clicked.connect(self.open_file)
        layout.addWidget(self.open_btn)

        # Export JSON button
        self.export_btn = QPushButton("Export JSON")
        self.export_btn.setMinimumWidth(100)
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_json)
        layout.addWidget(self.export_btn)

        return frame

    def create_left_panel(self) -> QWidget:
        """Create the left panel with package info."""
        group = QGroupBox("Package Information")
        layout = QVBoxLayout(group)

        # Package info tree
        self.info_tree = QTreeWidget()
        self.info_tree.setHeaderHidden(True)
        self.info_tree.setIndentation(20)
        layout.addWidget(self.info_tree)

        return group

    def create_right_panel(self) -> QWidget:
        """Create the right panel with tabs."""
        self.tabs = QTabWidget()

        # Classes tab
        self.classes_tree = QTreeWidget()
        self.classes_tree.setHeaderLabels(["Class / Method", "Type", "Offset"])
        self.classes_tree.setColumnWidth(0, 350)
        self.classes_tree.setColumnWidth(1, 80)
        self.classes_tree.setColumnWidth(2, 100)
        self.classes_tree.itemDoubleClicked.connect(self.on_method_double_clicked)
        self.tabs.addTab(self.classes_tree, "ObjC Classes")

        # Disassembly tab
        self.disasm_text = QTextEdit()
        self.disasm_text.setReadOnly(True)
        self.disasm_text.setFont(QFont("Consolas", 10))
        self.disasm_text.setStyleSheet("QTextEdit { background-color: #1e1e1e; color: #d4d4d4; }")
        self.tabs.addTab(self.disasm_text, "Disassembly")

        # Hooked Methods tab
        self.hooked_tree = QTreeWidget()
        self.hooked_tree.setHeaderLabels(["Class", "Method"])
        self.hooked_tree.setColumnWidth(0, 200)
        self.tabs.addTab(self.hooked_tree, "Hooked Methods")

        # Libraries tab
        self.libs_tree = QTreeWidget()
        self.libs_tree.setHeaderLabels(["Library Name"])
        self.tabs.addTab(self.libs_tree, "Imported Libraries")

        # Symbols tab
        self.symbols_tree = QTreeWidget()
        self.symbols_tree.setHeaderLabels(["Symbol", "Type"])
        self.symbols_tree.setColumnWidth(0, 400)
        self.tabs.addTab(self.symbols_tree, "Symbols")

        # Files tab
        self.files_tree = QTreeWidget()
        self.files_tree.setHeaderLabels(["File Path"])
        self.tabs.addTab(self.files_tree, "Package Files")

        # Strings tab
        self.strings_text = QTextEdit()
        self.strings_text.setReadOnly(True)
        self.strings_text.setFont(QFont("Consolas", 9))
        self.tabs.addTab(self.strings_text, "Strings")

        # JSON tab
        self.json_text = QTextEdit()
        self.json_text.setReadOnly(True)
        self.json_text.setFont(QFont("Consolas", 9))
        self.tabs.addTab(self.json_text, "JSON Output")

        return self.tabs


    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter event."""
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls and urls[0].toLocalFile().endswith(('.deb', '.dylib')):
                event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        """Handle drop event."""
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.analyze_file(Path(file_path))

    def open_file(self):
        """Open file dialog to select a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select .deb or .dylib file",
            "",
            "iOS Files (*.deb *.dylib);;Deb Packages (*.deb);;Dylib Files (*.dylib);;All Files (*)"
        )
        if file_path:
            self.analyze_file(Path(file_path))

    def analyze_file(self, file_path: Path):
        """Start analyzing the selected file."""
        self.current_file = file_path
        dylib_only = file_path.suffix.lower() == '.dylib'

        # Update UI
        self.file_label.setText(str(file_path))
        self.file_label.setStyleSheet("color: #333; font-style: normal;")
        self.clear_results()
        self.set_loading(True)

        # Start analysis in background thread
        self.analyzer_thread = AnalyzerThread(file_path, dylib_only)
        self.analyzer_thread.finished.connect(self.on_analysis_finished)
        self.analyzer_thread.error.connect(self.on_analysis_error)
        self.analyzer_thread.progress.connect(self.on_progress)
        self.analyzer_thread.start()

    def set_loading(self, loading: bool):
        """Set loading state."""
        self.open_btn.setEnabled(not loading)
        has_results = self.deb_contents is not None or self.dylib_analysis is not None
        self.export_btn.setEnabled(not loading and has_results)
        self.progress_bar.setVisible(loading)
        if loading:
            self.status_bar.showMessage("Analyzing...")

    def on_progress(self, message: str):
        """Handle progress updates."""
        self.status_bar.showMessage(message)

    def on_analysis_finished(self, deb_contents: Optional[DebContents], dylib_analysis: Optional[DylibAnalysis]):
        """Handle analysis completion."""
        self.deb_contents = deb_contents
        self.dylib_analysis = dylib_analysis
        self.set_loading(False)
        self.export_btn.setEnabled(True)
        self.populate_results()
        self.status_bar.showMessage("Analysis complete")

    def on_analysis_error(self, error_message: str):
        """Handle analysis error."""
        self.set_loading(False)
        self.status_bar.showMessage("Analysis failed")
        QMessageBox.critical(self, "Error", error_message)

    def clear_results(self):
        """Clear all result displays."""
        self.info_tree.clear()
        self.classes_tree.clear()
        self.hooked_tree.clear()
        self.libs_tree.clear()
        self.symbols_tree.clear()
        self.files_tree.clear()
        self.strings_text.clear()
        self.json_text.clear()
        self.disasm_text.clear()
        self.deb_contents = None
        self.dylib_analysis = None
        self.lief_binary = None
        self.dylib_path = None

    def populate_results(self):
        """Populate all result displays."""
        self.populate_info_tree()
        self.populate_classes_tree()
        self.populate_hooked_tree()
        self.populate_libs_tree()
        self.populate_symbols_tree()
        self.populate_files_tree()
        self.populate_strings()
        self.populate_json()

    def populate_info_tree(self):
        """Populate the package info tree."""
        self.info_tree.clear()

        if self.deb_contents:
            meta = self.deb_contents.metadata
            
            pkg_item = QTreeWidgetItem(["Package"])
            pkg_item.setFont(0, QFont("", -1, QFont.Weight.Bold))
            self.info_tree.addTopLevelItem(pkg_item)
            
            if meta.name or meta.package:
                QTreeWidgetItem(pkg_item, [f"Name: {meta.name or meta.package}"])
            if meta.version:
                QTreeWidgetItem(pkg_item, [f"Version: {meta.version}"])
            if meta.author:
                QTreeWidgetItem(pkg_item, [f"Author: {meta.author}"])
            if meta.architecture:
                QTreeWidgetItem(pkg_item, [f"Architecture: {meta.architecture}"])
            if meta.installed_size:
                size = meta.installed_size
                size_str = f"{size / 1024:.1f} MB" if size >= 1024 else f"{size} KB"
                QTreeWidgetItem(pkg_item, [f"Size: {size_str}"])
            if meta.description:
                QTreeWidgetItem(pkg_item, [f"Description: {meta.description}"])
            
            if self.deb_contents.plist_filter and "bundles" in self.deb_contents.plist_filter:
                bundles = self.deb_contents.plist_filter["bundles"]
                if bundles:
                    QTreeWidgetItem(pkg_item, [f"Target: {', '.join(bundles)}"])
            
            pkg_item.setExpanded(True)

        if self.dylib_analysis:
            header = self.dylib_analysis.header
            
            bin_item = QTreeWidgetItem(["Binary"])
            bin_item.setFont(0, QFont("", -1, QFont.Weight.Bold))
            self.info_tree.addTopLevelItem(bin_item)
            
            QTreeWidgetItem(bin_item, [f"Architecture: {header.arch}"])
            QTreeWidgetItem(bin_item, [f"Platform: {header.platform}"])
            if header.min_os_version:
                QTreeWidgetItem(bin_item, [f"Min OS: {header.min_os_version}"])
            QTreeWidgetItem(bin_item, [f"Type: {header.file_type}"])
            
            # Stats
            stats_item = QTreeWidgetItem(bin_item, ["Statistics"])
            QTreeWidgetItem(stats_item, [f"Classes: {len(self.dylib_analysis.objc_classes)}"])
            QTreeWidgetItem(stats_item, [f"Hooked Methods: {len(self.dylib_analysis.hooked_methods)}"])
            QTreeWidgetItem(stats_item, [f"Imported Libs: {len(self.dylib_analysis.imported_libs)}"])
            QTreeWidgetItem(stats_item, [f"Exported Symbols: {len(self.dylib_analysis.exported_symbols)}"])
            QTreeWidgetItem(stats_item, [f"Strings: {len(self.dylib_analysis.strings)}"])
            stats_item.setExpanded(True)
            
            bin_item.setExpanded(True)


    def populate_classes_tree(self):
        """Populate the ObjC classes tree."""
        self.classes_tree.clear()
        
        if not self.dylib_analysis:
            return

        hooked_set = set(self.dylib_analysis.hooked_methods)

        for cls in self.dylib_analysis.objc_classes:
            is_hooked_class = any(m.is_hooked for m in cls.methods)
            
            class_item = QTreeWidgetItem([cls.name, "class", ""])
            if is_hooked_class:
                class_item.setForeground(0, QColor("#e74c3c"))
                class_item.setText(1, "HOOKED")
            
            for method in cls.methods:
                prefix = "+" if method.is_class_method else "-"
                method_str = f"{prefix}[{cls.name} {method.name}]"
                
                # Format offset
                offset_str = ""
                if method.imp_offset:
                    offset_str = f"0x{method.imp_offset:X}"
                elif method.imp_address:
                    offset_str = f"0x{method.imp_address:X}"
                
                method_type = "class" if method.is_class_method else "instance"
                method_item = QTreeWidgetItem([method_str, method_type, offset_str])
                
                if method.is_hooked:
                    method_item.setForeground(0, QColor("#e74c3c"))
                    method_item.setText(1, "HOOKED")
                
                class_item.addChild(method_item)
            
            self.classes_tree.addTopLevelItem(class_item)

    def populate_hooked_tree(self):
        """Populate the hooked methods tree."""
        self.hooked_tree.clear()
        
        if not self.dylib_analysis:
            return

        for cls_name, method_name in self.dylib_analysis.hooked_methods:
            item = QTreeWidgetItem([cls_name, method_name])
            item.setForeground(0, QColor("#e74c3c"))
            item.setForeground(1, QColor("#e74c3c"))
            self.hooked_tree.addTopLevelItem(item)

    def populate_libs_tree(self):
        """Populate the imported libraries tree."""
        self.libs_tree.clear()
        
        if not self.dylib_analysis:
            return

        for lib in self.dylib_analysis.imported_libs:
            QTreeWidgetItem(self.libs_tree, [lib])

    def populate_symbols_tree(self):
        """Populate the symbols tree."""
        self.symbols_tree.clear()
        
        if not self.dylib_analysis:
            return

        # Exported symbols
        if self.dylib_analysis.exported_symbols:
            export_item = QTreeWidgetItem([f"Exported ({len(self.dylib_analysis.exported_symbols)})", ""])
            export_item.setFont(0, QFont("", -1, QFont.Weight.Bold))
            for symbol in self.dylib_analysis.exported_symbols:
                QTreeWidgetItem(export_item, [symbol, "export"])
            self.symbols_tree.addTopLevelItem(export_item)
            export_item.setExpanded(True)

        # Imported symbols
        if self.dylib_analysis.imported_symbols:
            import_item = QTreeWidgetItem([f"Imported ({len(self.dylib_analysis.imported_symbols)})", ""])
            import_item.setFont(0, QFont("", -1, QFont.Weight.Bold))
            for symbol in self.dylib_analysis.imported_symbols[:500]:  # Limit for performance
                QTreeWidgetItem(import_item, [symbol, "import"])
            if len(self.dylib_analysis.imported_symbols) > 500:
                QTreeWidgetItem(import_item, [f"... and {len(self.dylib_analysis.imported_symbols) - 500} more", ""])
            self.symbols_tree.addTopLevelItem(import_item)

    def populate_files_tree(self):
        """Populate the package files tree."""
        self.files_tree.clear()
        
        if not self.deb_contents:
            return

        for file_path in self.deb_contents.files:
            item = QTreeWidgetItem([file_path])
            if file_path.endswith('.dylib'):
                item.setForeground(0, QColor("#3498db"))
            elif file_path.endswith('.plist'):
                item.setForeground(0, QColor("#9b59b6"))
            self.files_tree.addTopLevelItem(item)

    def populate_strings(self):
        """Populate the strings text area."""
        self.strings_text.clear()
        
        if not self.dylib_analysis:
            return

        strings = self.dylib_analysis.strings
        self.strings_text.setPlainText("\n".join(strings))

    def populate_json(self):
        """Populate the JSON output."""
        self.json_text.clear()
        
        report_gen = ReportGenerator()
        json_str = report_gen.to_json(self.deb_contents, self.dylib_analysis)
        self.json_text.setPlainText(json_str)

    def export_json(self):
        """Export analysis results to JSON file."""
        if not self.deb_contents and not self.dylib_analysis:
            return

        default_name = self.current_file.stem + "_analysis.json" if self.current_file else "analysis.json"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save JSON Report",
            default_name,
            "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            report_gen = ReportGenerator()
            json_str = report_gen.to_json(self.deb_contents, self.dylib_analysis)
            Path(file_path).write_text(json_str, encoding="utf-8")
            self.status_bar.showMessage(f"Exported to {file_path}")
            QMessageBox.information(self, "Export Complete", f"Report saved to:\n{file_path}")

    def on_method_double_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle double-click on a method to show disassembly."""
        # Check if it's a method (has offset in column 2)
        offset_str = item.text(2)
        if not offset_str or not offset_str.startswith("0x"):
            return
        
        try:
            offset = int(offset_str, 16)
        except ValueError:
            return
        
        method_name = item.text(0)
        self.disassemble_at_offset(offset, method_name)
        
        # Switch to disassembly tab
        self.tabs.setCurrentWidget(self.disasm_text)

    def disassemble_at_offset(self, offset: int, method_name: str = ""):
        """Disassemble code at the given offset."""
        self.disasm_text.clear()
        
        # Get the dylib path
        dylib_path = self._get_dylib_path()
        if not dylib_path or not dylib_path.exists():
            self.disasm_text.setPlainText("Error: Could not find dylib file for disassembly")
            return
        
        try:
            import lief
            try:
                from .disassembler import Disassembler
            except ImportError:
                from ios_deb_analyzer.disassembler import Disassembler
            
            # Load binary if not already loaded
            if self.lief_binary is None:
                self.lief_binary = lief.parse(str(dylib_path))
                if isinstance(self.lief_binary, lief.MachO.FatBinary):
                    self.lief_binary = self.lief_binary.at(0)
            
            disasm = Disassembler(self.lief_binary)
            disasm.load_file(dylib_path)
            
            instructions = disasm.disassemble_at_offset(offset, 512)
            
            # Format output with syntax highlighting
            lines = []
            if method_name:
                lines.append(f"; {method_name}")
                lines.append(f"; Offset: 0x{offset:X}")
                lines.append("")
            
            for insn in instructions:
                hex_bytes = ' '.join(f'{b:02X}' for b in insn.bytes)
                line = f"0x{insn.address:08X}:  {hex_bytes:<12}  {insn.mnemonic:<8} {insn.op_str}"
                lines.append(line)
                
                # Stop at RET instruction
                if insn.mnemonic == 'ret':
                    lines.append("")
                    lines.append("; --- End of function ---")
                    break
            
            self.disasm_text.setPlainText('\n'.join(lines))
            self.status_bar.showMessage(f"Disassembled {len(instructions)} instructions at 0x{offset:X}")
            
        except Exception as e:
            self.disasm_text.setPlainText(f"Error during disassembly: {e}")

    def _get_dylib_path(self) -> Optional[Path]:
        """Get the path to the dylib file."""
        if self.dylib_path and self.dylib_path.exists():
            return self.dylib_path
        
        # If analyzing dylib directly
        if self.current_file and self.current_file.suffix.lower() == '.dylib':
            return self.current_file
        
        # If analyzing deb, need to extract dylib
        if self.current_file and self.deb_contents and self.deb_contents.dylib_paths:
            import tempfile
            try:
                from .deb_parser import DebParser
            except ImportError:
                from ios_deb_analyzer.deb_parser import DebParser
            
            # Create persistent temp directory for this session
            if not hasattr(self, '_temp_dir') or self._temp_dir is None:
                self._temp_dir = tempfile.mkdtemp()
            
            parser = DebParser()
            extract_path = parser.extract_to(self.current_file, Path(self._temp_dir))
            
            for dylib_rel_path in self.deb_contents.dylib_paths:
                full_path = extract_path / dylib_rel_path
                if full_path.exists():
                    self.dylib_path = full_path
                    return full_path
        
        return None


def main():
    """Main entry point for GUI application."""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set application-wide font
    font = app.font()
    font.setPointSize(10)
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
