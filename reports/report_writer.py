"""
rabbitRecon Report Writer
Unified reporting system for all modules
Supports multiple output formats and templates
"""

import json
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from utils.logger import get_logger

logger = get_logger('report_writer')

class ReportWriter:
    """Handle report generation in multiple formats"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize report writer with configuration

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.template_dir = Path(__file__).parent / 'templates'
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=True
        )

        # Register custom filters
        self.env.filters['format_timestamp'] = self._format_timestamp

    def _format_timestamp(self, value: Any) -> str:
        """Jinja2 filter to format timestamps"""
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value).isoformat()
        return str(value)

    def write_report(self, data: Dict, output_path: str,
                    format: str = 'json') -> bool:
        """
        Write report data to file in specified format

        Args:
            data: Data to write
            output_path: Output file path
            format: Output format (json/yaml/html/text)

        Returns:
            True if successful, False otherwise
        """
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if format == 'json':
                self._write_json(data, output_path)
            elif format == 'yaml':
                self._write_yaml(data, output_path)
            elif format == 'html':
                self._write_html(data, output_path)
            elif format == 'text':
                self._write_text(data, output_path)
            else:
                raise ValueError(f"Unsupported format: {format}")

            logger.info(f"Report written to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to write report: {str(e)}")
            return False

    def _write_json(self, data: Dict, output_path: Path) -> None:
        """Write report data as JSON"""
        with output_path.open('w') as f:
            json.dump(data, f, indent=2)

    def _write_yaml(self, data: Dict, output_path: Path) -> None:
        """Write report data as YAML"""
        with output_path.open('w') as f:
            yaml.safe_dump(data, f, default_flow_style=False)

    def _write_html(self, data: Dict, output_path: Path) -> None:
        """Write report data as HTML using template"""
        template = self.env.get_template('default.html.j2')

        # Add metadata
        report_data = {
            'generated_at': datetime.now(),
            'tool_name': 'reconx',
            'data': data
        }

        html = template.render(report_data)
        with output_path.open('w') as f:
            f.write(html)

    def _write_text(self, data: Dict, output_path: Path) -> None:
        """Write report data as formatted text"""
        template = self.env.get_template('default.txt.j2')
        text = template.render(data)
        with output_path.open('w') as f:
            f.write(text)

    def format_console(self, data: Dict) -> str:
        """
        Format data for console output

        Args:
            data: Data to format

        Returns:
            Formatted string
        """
        template = self.env.get_template('console.txt.j2')
        return template.render(data)

def write_report(data: Dict, output_path: str, format: str = 'json') -> bool:
    """
    Convenience function for writing reports

    Args:
        data: Data to write
        output_path: Output file path
        format: Output format (json/yaml/html/text)

    Returns:
        True if successful, False otherwise
    """
    writer = ReportWriter()
    return writer.write_report(data, output_path, format)
