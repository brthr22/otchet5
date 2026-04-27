"""
GUI module for RedCheck Protocol Generator.

This module provides a Tkinter-based graphical user interface for:
- Selecting input XML report files
- Selecting output DOCX template and destination
- Running the document generation process
- Viewing progress and error reports
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import threading
import logging
from typing import Optional, Callable
from datetime import datetime

from parsers.inventory_parser import InventoryParser
from parsers.pentest_parser import PentestParser
from parsers.vulnerability_parser import VulnerabilityParser
from parsers import ParsedData
from doc_generator import DocumentGenerator


class ApplicationLogger:
    """Custom logger that writes to both file and GUI text widget."""

    def __init__(self, log_file: str):
        self.log_file = log_file
        self.text_widget: Optional[scrolledtext.ScrolledText] = None
        self.logger = logging.getLogger("RedCheckApp")
        self.logger.setLevel(logging.DEBUG)

        # File handler
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)

    def set_text_widget(self, widget: scrolledtext.ScrolledText):
        """Set the text widget for GUI logging."""
        self.text_widget = widget

    def log(self, level: int, message: str):
        """Log a message."""
        self.logger.log(level, message)
        if self.text_widget:
            timestamp = datetime.now().strftime('%H:%M:%S')
            level_name = logging.getLevelName(level)
            self.text_widget.insert(tk.END, f"[{timestamp}] {level_name}: {message}\n")
            self.text_widget.see(tk.END)

    def info(self, message: str):
        self.log(logging.INFO, message)

    def warning(self, message: str):
        self.log(logging.WARNING, message)

    def error(self, message: str):
        self.log(logging.ERROR, message)

    def debug(self, message: str):
        self.log(logging.DEBUG, message)


class RedCheckApp:
    """Main application class for RedCheck Protocol Generator."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("RedCheck Protocol Generator v1.0")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        # Initialize paths
        self.inventory_files: list[str] = []
        self.pentest_files: list[str] = []
        self.vulnerability_files: list[str] = []
        self.template_path: str = ""
        self.output_path: str = ""

        # Setup logging
        log_dir = Path(__file__).parent / "logs"
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / f"app_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.app_logger = ApplicationLogger(str(log_file))

        # Build UI
        self._create_ui()

    def _create_ui(self):
        """Create the main user interface."""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # File selection section
        self._create_file_selection_section(main_frame)

        # Progress section
        self._create_progress_section(main_frame)

        # Log section
        self._create_log_section(main_frame)

        # Action buttons
        self._create_action_buttons(main_frame)

    def _create_file_selection_section(self, parent: ttk.Frame):
        """Create file selection widgets."""
        files_frame = ttk.LabelFrame(parent, text="Input Files", padding="5")
        files_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        parent.columnconfigure(0, weight=1)

        # Inventory reports
        ttk.Label(files_frame, text="Inventory Reports (XML):").grid(
            row=0, column=0, sticky=tk.W, pady=2
        )
        self.inventory_var = tk.StringVar(value="No files selected")
        ttk.Entry(files_frame, textvariable=self.inventory_var, state='readonly', width=60).grid(
            row=0, column=1, padx=5, pady=2, sticky=(tk.W, tk.E)
        )
        ttk.Button(files_frame, text="Browse...", command=self._browse_inventory).grid(
            row=0, column=2, pady=2
        )

        # Pentest reports
        ttk.Label(files_frame, text="Pentest Reports (XML):").grid(
            row=1, column=0, sticky=tk.W, pady=2
        )
        self.pentest_var = tk.StringVar(value="No files selected")
        ttk.Entry(files_frame, textvariable=self.pentest_var, state='readonly', width=60).grid(
            row=1, column=1, padx=5, pady=2, sticky=(tk.W, tk.E)
        )
        ttk.Button(files_frame, text="Browse...", command=self._browse_pentest).grid(
            row=1, column=2, pady=2
        )

        # Vulnerability reports
        ttk.Label(files_frame, text="Vulnerability Reports (XML):").grid(
            row=2, column=0, sticky=tk.W, pady=2
        )
        self.vuln_var = tk.StringVar(value="No files selected")
        ttk.Entry(files_frame, textvariable=self.vuln_var, state='readonly', width=60).grid(
            row=2, column=1, padx=5, pady=2, sticky=(tk.W, tk.E)
        )
        ttk.Button(files_frame, text="Browse...", command=self._browse_vulnerability).grid(
            row=2, column=2, pady=2
        )

        files_frame.columnconfigure(1, weight=1)

    def _create_template_section(self, parent: ttk.Frame):
        """Create template selection widgets."""
        template_frame = ttk.LabelFrame(parent, text="Template & Output", padding="5")
        template_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        parent.columnconfigure(0, weight=1)

        # Template file
        ttk.Label(template_frame, text="DOCX Template:").grid(
            row=0, column=0, sticky=tk.W, pady=2
        )
        self.template_var = tk.StringVar(value="No template selected")
        ttk.Entry(template_frame, textvariable=self.template_var, state='readonly', width=60).grid(
            row=0, column=1, padx=5, pady=2, sticky=(tk.W, tk.E)
        )
        ttk.Button(template_frame, text="Browse...", command=self._browse_template).grid(
            row=0, column=2, pady=2
        )

        # Output file
        ttk.Label(template_frame, text="Output File:").grid(
            row=1, column=0, sticky=tk.W, pady=2
        )
        self.output_var = tk.StringVar(value="")
        ttk.Entry(template_frame, textvariable=self.output_var, width=60).grid(
            row=1, column=1, padx=5, pady=2, sticky=(tk.W, tk.E)
        )
        ttk.Button(template_frame, text="Browse...", command=self._browse_output).grid(
            row=1, column=2, pady=2
        )

        template_frame.columnconfigure(1, weight=1)

    def _create_progress_section(self, parent: ttk.Frame):
        """Create progress bar and status label."""
        progress_frame = ttk.Frame(parent)
        progress_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame, variable=self.progress_var, maximum=100, mode='determinate'
        )
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5)
        progress_frame.columnconfigure(0, weight=1)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(progress_frame, textvariable=self.status_var).grid(
            row=1, column=0, sticky=tk.W, padx=5, pady=2
        )

    def _create_log_section(self, parent: ttk.Frame):
        """Create log output area."""
        log_frame = ttk.LabelFrame(parent, text="Log Output", padding="5")
        log_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        # Connect logger to text widget
        self.app_logger.set_text_widget(self.log_text)

    def _create_action_buttons(self, parent: ttk.Frame):
        """Create action buttons."""
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        self.generate_btn = ttk.Button(
            button_frame, text="Generate Protocol", command=self._start_generation
        )
        self.generate_btn.grid(row=0, column=0, padx=5)

        ttk.Button(button_frame, text="Clear Log", command=self._clear_log).grid(
            row=0, column=1, padx=5
        )

        ttk.Button(button_frame, text="Exit", command=self._exit_app).grid(
            row=0, column=2, padx=5
        )

    def _browse_inventory(self):
        """Browse for inventory report files."""
        files = filedialog.askopenfilenames(
            title="Select Inventory Reports",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")]
        )
        if files:
            self.inventory_files = list(files)
            self.inventory_var.set(f"{len(files)} file(s) selected")
            self.app_logger.info(f"Selected {len(files)} inventory report(s)")

    def _browse_pentest(self):
        """Browse for pentest report files."""
        files = filedialog.askopenfilenames(
            title="Select Pentest Reports",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")]
        )
        if files:
            self.pentest_files = list(files)
            self.pentest_var.set(f"{len(files)} file(s) selected")
            self.app_logger.info(f"Selected {len(files)} pentest report(s)")

    def _browse_vulnerability(self):
        """Browse for vulnerability report files."""
        files = filedialog.askopenfilenames(
            title="Select Vulnerability Reports",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")]
        )
        if files:
            self.vulnerability_files = list(files)
            self.vuln_var.set(f"{len(files)} file(s) selected")
            self.app_logger.info(f"Selected {len(files)} vulnerability report(s)")

    def _browse_template(self):
        """Browse for DOCX template file."""
        file = filedialog.askopenfilename(
            title="Select DOCX Template",
            filetypes=[("Word documents", "*.docx"), ("All files", "*.*")]
        )
        if file:
            self.template_path = file
            self.template_var.set(Path(file).name)
            self.app_logger.info(f"Selected template: {file}")

            # Auto-set default output path
            if not self.output_path:
                output_dir = Path(file).parent
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                self.output_path = str(output_dir / f"SecurityProtocol_{timestamp}.docx")
                self.output_var.set(self.output_path)

    def _browse_output(self):
        """Browse for output file location."""
        file = filedialog.asksaveasfilename(
            title="Save Output As",
            defaultextension=".docx",
            filetypes=[("Word documents", "*.docx"), ("All files", "*.*")],
            initialfile=f"SecurityProtocol_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
        )
        if file:
            self.output_path = file
            self.output_var.set(file)
            self.app_logger.info(f"Output will be saved to: {file}")

    def _clear_log(self):
        """Clear the log output."""
        self.log_text.delete(1.0, tk.END)
        self.app_logger.info("Log cleared")

    def _exit_app(self):
        """Exit the application."""
        if messagebox.askyesno("Confirm Exit", "Are you sure you want to exit?"):
            self.root.quit()
            self.root.destroy()

    def _start_generation(self):
        """Start document generation in a separate thread."""
        # Validate inputs
        if not any([self.inventory_files, self.pentest_files, self.vulnerability_files]):
            messagebox.showerror(
                "Error",
                "Please select at least one input report file."
            )
            return

        if not self.template_path:
            messagebox.showerror(
                "Error",
                "Please select a DOCX template file."
            )
            return

        if not self.output_path:
            messagebox.showerror(
                "Error",
                "Please specify an output file path."
            )
            return

        # Disable generate button during processing
        self.generate_btn.config(state='disabled')
        self.progress_var.set(0)
        self.status_var.set("Processing...")

        # Start generation in background thread
        thread = threading.Thread(target=self._run_generation, daemon=True)
        thread.start()

    def _run_generation(self):
        """Run the document generation process."""
        try:
            all_data = ParsedData()

            # Parse inventory reports
            if self.inventory_files:
                self._update_status("Parsing inventory reports...")
                self._update_progress(10)
                for i, file_path in enumerate(self.inventory_files):
                    self.app_logger.info(f"Parsing inventory: {Path(file_path).name}")
                    parser = InventoryParser(file_path)
                    data = parser.parse()
                    all_data.hosts.extend(data.hosts)
                    all_data.errors.extend(data.errors)
                    all_data.warnings.extend(data.warnings)
                    progress = 10 + (i + 1) * 20 / max(len(self.inventory_files), 1)
                    self._update_progress(progress)

            # Parse pentest reports
            if self.pentest_files:
                self._update_status("Parsing pentest reports...")
                for i, file_path in enumerate(self.pentest_files):
                    self.app_logger.info(f"Parsing pentest: {Path(file_path).name}")
                    parser = PentestParser(file_path)
                    data = parser.parse()
                    all_data.port_scans.extend(data.port_scans)
                    all_data.scan_metadata.update(data.scan_metadata)
                    all_data.errors.extend(data.errors)
                    all_data.warnings.extend(data.warnings)
                    progress = 30 + (i + 1) * 20 / max(len(self.pentest_files), 1)
                    self._update_progress(progress)

            # Parse vulnerability reports
            if self.vulnerability_files:
                self._update_status("Parsing vulnerability reports...")
                for i, file_path in enumerate(self.vulnerability_files):
                    self.app_logger.info(f"Parsing vulnerabilities: {Path(file_path).name}")
                    parser = VulnerabilityParser(file_path)
                    data = parser.parse()
                    all_data.vulnerabilities.extend(data.vulnerabilities)
                    all_data.scan_metadata.update(data.scan_metadata)
                    all_data.errors.extend(data.errors)
                    all_data.warnings.extend(data.warnings)
                    progress = 50 + (i + 1) * 20 / max(len(self.vulnerability_files), 1)
                    self._update_progress(progress)

            # Generate document
            self._update_status("Generating document...")
            self._update_progress(70)

            generator = DocumentGenerator(self.template_path)
            success = generator.fill_document(all_data, self.output_path)

            if success:
                self._update_progress(100)
                self._update_status("Completed successfully!")
                self.app_logger.info(f"Document generated: {self.output_path}")

                # Log warnings and errors
                for warning in generator.get_warnings():
                    self.app_logger.warning(warning)
                for error in generator.get_errors():
                    self.app_logger.error(error)

                # Show summary
                summary = (
                    f"Generation Complete!\n\n"
                    f"Hosts: {len(all_data.hosts)}\n"
                    f"Port Scans: {len(all_data.port_scans)}\n"
                    f"Vulnerabilities: {len(all_data.vulnerabilities)}\n"
                    f"Errors: {len(all_data.errors) + len(generator.get_errors())}\n"
                    f"Warnings: {len(all_data.warnings) + len(generator.get_warnings())}\n\n"
                    f"Output: {self.output_path}"
                )
                self.root.after(0, lambda: messagebox.showinfo("Success", summary))
            else:
                self._update_status("Generation failed!")
                self.app_logger.error("Document generation failed")
                error_msg = "\n".join(generator.get_errors())
                self.root.after(0, lambda: messagebox.showerror("Error", error_msg))

        except Exception as e:
            self.app_logger.error(f"Unexpected error: {e}")
            self._update_status("Error occurred!")
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

        finally:
            self.root.after(0, self._enable_generate_button)

    def _update_status(self, status: str):
        """Update status label (thread-safe)."""
        self.root.after(0, lambda: self.status_var.set(status))

    def _update_progress(self, value: float):
        """Update progress bar (thread-safe)."""
        self.root.after(0, lambda: self.progress_var.set(value))

    def _enable_generate_button(self):
        """Re-enable the generate button."""
        self.generate_btn.config(state='normal')


def run_app():
    """Run the application."""
    root = tk.Tk()

    # Set theme
    style = ttk.Style()
    if 'clam' in style.theme_names():
        style.theme_use('clam')

    app = RedCheckApp(root)
    root.mainloop()


if __name__ == "__main__":
    run_app()
