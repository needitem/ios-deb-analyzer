"""CLI interface module.

This module provides the command-line interface using click.
"""

import sys
import tempfile
import time
from pathlib import Path

import click

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


@click.group()
@click.version_option()
def main():
    """iOS Deb Analyzer - Analyze iOS .deb packages and dylib binaries."""
    pass


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--dylib-only", is_flag=True, help="Analyze dylib file directly")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
@click.option("--json", "json_output", is_flag=True, help="Output in JSON format")
@click.option("--output", "-o", type=click.Path(), help="Save output to file")
def analyze(file_path: str, dylib_only: bool, verbose: bool, json_output: bool, output: str | None):
    """Analyze a .deb package or dylib file.
    
    FILE_PATH: Path to the .deb or .dylib file to analyze
    
    Examples:
    
    \b
      ios-deb-analyzer analyze package.deb
      ios-deb-analyzer analyze package.deb --json --output report.json
      ios-deb-analyzer analyze tweak.dylib --dylib-only
      ios-deb-analyzer analyze package.deb --verbose
    """
    file_path = Path(file_path)
    deb_parser = DebParser()
    dylib_analyzer = DylibAnalyzer()
    report_generator = ReportGenerator()
    
    deb_contents: DebContents | None = None
    dylib_analysis: DylibAnalysis | None = None
    
    try:
        if dylib_only:
            # Analyze dylib file directly
            dylib_analysis = dylib_analyzer.analyze(file_path)
        else:
            # Analyze deb package
            deb_contents = deb_parser.parse(file_path)
            
            # If deb contains dylib files, analyze the first one
            if deb_contents.dylib_paths:
                # Extract deb to temp directory and analyze dylib
                with tempfile.TemporaryDirectory() as temp_dir:
                    extract_path = deb_parser.extract_to(file_path, Path(temp_dir))
                    
                    # Find and analyze the first dylib
                    for dylib_path in deb_contents.dylib_paths:
                        full_dylib_path = extract_path / dylib_path
                        if full_dylib_path.exists():
                            dylib_analysis = dylib_analyzer.analyze(full_dylib_path)
                            break
        
        # Generate output
        if json_output:
            json_str = report_generator.to_json(deb_contents, dylib_analysis)
            if output:
                report_generator.save_to_file(json_str, Path(output))
                click.echo(f"Report saved to {output}")
            else:
                click.echo(json_str)
        else:
            report_generator.print_terminal(deb_contents, dylib_analysis, verbose=verbose)
            if output:
                # Save terminal output as text (without colors)
                json_str = report_generator.to_json(deb_contents, dylib_analysis)
                report_generator.save_to_file(json_str, Path(output))
                click.echo(f"\nReport saved to {output}")
                
    except InvalidDebError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except InvalidMachOError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except PermissionError as e:
        click.echo(f"Error: Permission denied - {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: An unexpected error occurred - {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
