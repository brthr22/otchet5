#!/usr/bin/env python3
"""
Main entry point for RedCheck Protocol Generator.

This script launches the GUI application or can be used for command-line processing.
"""

import sys
import argparse
from pathlib import Path


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="RedCheck Protocol Generator - Generate security protocols from RedCheck reports"
    )
    
    parser.add_argument(
        "--inventory", "-i",
        nargs="+",
        help="Inventory XML report files"
    )
    parser.add_argument(
        "--pentest", "-p",
        nargs="+",
        help="Pentest XML report files"
    )
    parser.add_argument(
        "--vulnerability", "-v",
        nargs="+",
        help="Vulnerability XML report files"
    )
    parser.add_argument(
        "--template", "-t",
        required=False,
        help="DOCX template file"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output DOCX file path"
    )
    parser.add_argument(
        "--gui", "-g",
        action="store_true",
        help="Launch GUI application"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # If no arguments provided, launch GUI
    if len(sys.argv) == 1 or args.gui:
        launch_gui()
        return
    
    # Command-line mode requires at least one input and template
    if not any([args.inventory, args.pentest, args.vulnerability]):
        parser.error("At least one input file (--inventory, --pentest, or --vulnerability) is required")
    
    if not args.template:
        parser.error("--template is required in command-line mode")
    
    if not args.output:
        parser.error("--output is required in command-line mode")
    
    # Run in command-line mode
    run_cli(args)


def launch_gui():
    """Launch the GUI application."""
    try:
        import tkinter as tk
        from gui.app import RedCheckApp
        
        root = tk.Tk()
        
        # Set theme
        style = ttk_style_available()
        if style:
            from tkinter import ttk
            s = ttk.Style()
            if style in s.theme_names():
                s.theme_use(style)
        
        app = RedCheckApp(root)
        root.mainloop()
        
    except ImportError as e:
        print(f"Error: GUI dependencies not available: {e}")
        print("Please ensure tkinter is installed.")
        sys.exit(1)
    except Exception as e:
        print(f"Error launching GUI: {e}")
        sys.exit(1)


def ttk_style_available():
    """Check for available ttk themes."""
    try:
        from tkinter import ttk
        s = ttk.Style()
        themes = s.theme_names()
        if 'clam' in themes:
            return 'clam'
        elif 'vista' in themes:
            return 'vista'
        return themes[0] if themes else None
    except:
        return None


def run_cli(args):
    """Run in command-line mode."""
    import logging
    from datetime import datetime
    from parsers.inventory_parser import InventoryParser
    from parsers.pentest_parser import PentestParser
    from parsers.vulnerability_parser import VulnerabilityParser
    from parsers import ParsedData
    from doc_generator import DocumentGenerator
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger(__name__)
    
    all_data = ParsedData()
    
    # Parse inventory reports
    if args.inventory:
        logger.info(f"Parsing {len(args.inventory)} inventory report(s)...")
        for file_path in args.inventory:
            try:
                parser = InventoryParser(file_path)
                data = parser.parse()
                all_data.hosts.extend(data.hosts)
                all_data.errors.extend(data.errors)
                all_data.warnings.extend(data.warnings)
                logger.info(f"  - {Path(file_path).name}: {len(data.hosts)} host(s)")
            except Exception as e:
                logger.error(f"Error parsing {file_path}: {e}")
    
    # Parse pentest reports
    if args.pentest:
        logger.info(f"Parsing {len(args.pentest)} pentest report(s)...")
        for file_path in args.pentest:
            try:
                parser = PentestParser(file_path)
                data = parser.parse()
                all_data.port_scans.extend(data.port_scans)
                all_data.scan_metadata.update(data.scan_metadata)
                all_data.errors.extend(data.errors)
                all_data.warnings.extend(data.warnings)
                logger.info(f"  - {Path(file_path).name}: {len(data.port_scans)} host(s)")
            except Exception as e:
                logger.error(f"Error parsing {file_path}: {e}")
    
    # Parse vulnerability reports
    if args.vulnerability:
        logger.info(f"Parsing {len(args.vulnerability)} vulnerability report(s)...")
        for file_path in args.vulnerability:
            try:
                parser = VulnerabilityParser(file_path)
                data = parser.parse()
                all_data.vulnerabilities.extend(data.vulnerabilities)
                all_data.scan_metadata.update(data.scan_metadata)
                all_data.errors.extend(data.errors)
                all_data.warnings.extend(data.warnings)
                logger.info(f"  - {Path(file_path).name}: {len(data.vulnerabilities)} vuln(s)")
            except Exception as e:
                logger.error(f"Error parsing {file_path}: {e}")
    
    # Generate document
    logger.info(f"Generating document using template: {args.template}")
    generator = DocumentGenerator(args.template)
    
    if not generator.load_template():
        logger.error("Failed to load template")
        sys.exit(1)
    
    if not generator.fill_document(all_data, args.output):
        logger.error("Failed to generate document")
        for error in generator.get_errors():
            logger.error(f"  - {error}")
        sys.exit(1)
    
    # Summary
    print("\n" + "="*60)
    print("GENERATION COMPLETE")
    print("="*60)
    print(f"Hosts:           {len(all_data.hosts)}")
    print(f"Port Scans:      {len(all_data.port_scans)}")
    print(f"Vulnerabilities: {len(all_data.vulnerabilities)}")
    print(f"Errors:          {len(all_data.errors) + len(generator.get_errors())}")
    print(f"Warnings:        {len(all_data.warnings) + len(generator.get_warnings())}")
    print(f"\nOutput: {args.output}")
    print("="*60)
    
    if args.verbose:
        if all_data.warnings or generator.get_warnings():
            print("\nWarnings:")
            for w in all_data.warnings + generator.get_warnings():
                print(f"  - {w}")
        if all_data.errors or generator.get_errors():
            print("\nErrors:")
            for e in all_data.errors + generator.get_errors():
                print(f"  - {e}")


if __name__ == "__main__":
    main()
