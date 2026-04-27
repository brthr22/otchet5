#!/usr/bin/env python3
"""
RedCheck Protocol Generator - Main Entry Point

Usage:
    python main.py --gui                    # Launch GUI
    python main.py -i inv.xml -p p.xml -v v.xml -t template.docx -o out.docx  # CLI mode
    python main.py --create-template        # Create sample template
"""

import sys
import argparse
import logging
from pathlib import Path

# Add package to path
sys.path.insert(0, str(Path(__file__).parent))

from core.models import Host, PortScan, Vulnerability
from parsers.inventory_parser import InventoryParser
from parsers.pentest_parser import PentestParser
from parsers.vulnerability_parser import VulnerabilityParser
from doc_generator import DocumentGenerator, create_sample_template


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    format_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    handlers = [
        logging.StreamHandler(sys.stdout),
    ]
    
    # Also log to file
    log_dir = Path(__file__).parent / 'logs'
    log_dir.mkdir(exist_ok=True)
    handlers.append(logging.FileHandler(log_dir / 'app.log', encoding='utf-8'))
    
    logging.basicConfig(
        level=level,
        format=format_str,
        handlers=handlers
    )


def cli_mode(args):
    """Run in CLI mode."""
    logger = logging.getLogger(__name__)
    
    # Validate inputs
    if not args.template.exists():
        print(f"Error: Template not found: {args.template}")
        return 1
    
    # Parse files
    hosts_data = []
    
    # Parse inventory
    host = None
    if args.inventory and args.inventory.exists():
        try:
            parser = InventoryParser()
            hosts = parser.parse(args.inventory)
            if hosts:
                host = hosts[0]
                logger.info(f"Parsed inventory: {host.hostname or host.ip}")
        except Exception as e:
            logger.error(f"Inventory parse error: {e}")
    
    # Parse pentest
    port_scan = None
    if args.pentest and args.pentest.exists():
        try:
            parser = PentestParser()
            scans = parser.parse(args.pentest)
            if scans:
                port_scan = scans[0]
                logger.info(f"Parsed pentest: {len(port_scan.open_ports)} ports")
        except Exception as e:
            logger.error(f"Pentest parse error: {e}")
    
    # Parse vulnerabilities
    vulnerabilities = []
    scan_metadata = None
    if args.vulns and args.vulns.exists():
        try:
            parser = VulnerabilityParser()
            vulns, metadata = parser.parse(args.vulns)
            vulnerabilities = vulns
            scan_metadata = metadata
            logger.info(f"Parsed vulnerabilities: {len(vulns)} items")
        except Exception as e:
            logger.error(f"Vulnerabilities parse error: {e}")
    
    # Generate document
    try:
        generator = DocumentGenerator(args.template)
        generator.generate(args.output, [{
            'host': host,
            'port_scan': port_scan,
            'vulnerabilities': vulnerabilities,
            'scan_metadata': scan_metadata,
            'errors': []
        }])
        logger.info(f"Document generated: {args.output}")
        print(f"\n✓ Protocol generated successfully: {args.output}")
        return 0
    except Exception as e:
        logger.exception("Generation failed")
        print(f"\n✗ Generation failed: {e}")
        return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='RedCheck Protocol Generator - Автоматическое формирование протокола ИБ',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --gui                                    Запустить графический интерфейс
  %(prog)s --create-template -t template.docx       Создать образец шаблона
  %(prog)s -i inv.xml -p scan.xml -v vuln.xml -t template.docx -o protocol.docx
        """
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--gui', action='store_true', help='Запустить GUI')
    mode_group.add_argument('--create-template', action='store_true', help='Создать шаблон документа')
    
    # Input files (for CLI mode)
    parser.add_argument('-i', '--inventory', type=Path, help='Отчет инвентаризации (XML)')
    parser.add_argument('-p', '--pentest', type=Path, help='Отчет пентеста/скана портов')
    parser.add_argument('-v', '--vulns', type=Path, help='Отчет уязвимостей (XML)')
    
    # Template and output
    parser.add_argument('-t', '--template', type=Path, default='template.docx', 
                       help='Шаблон DOCX (по умолчанию: template.docx)')
    parser.add_argument('-o', '--output', type=Path, default='protocol.docx',
                       help='Выходной файл (по умолчанию: protocol.docx)')
    
    # Options
    parser.add_argument('-V', '--verbose', action='store_true', help='Подробный вывод')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    logger.info("RedCheck Protocol Generator started")
    
    # Handle modes
    if args.gui:
        from gui.app import run_gui
        run_gui()
    
    elif args.create_template:
        output = args.output if args.output != Path('protocol.docx') else Path('template.docx')
        create_sample_template(output)
        print(f"✓ Sample template created: {output}")
    
    else:
        # CLI mode - require at least one input file
        if not any([args.inventory, args.pentest, args.vulns]):
            parser.print_help()
            print("\nError: Specify at least one input file (-i, -p, or -v)")
            return 1
        
        return cli_mode(args)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
