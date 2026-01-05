"""Report generator module.

This module handles formatting and output of analysis results.
"""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.text import Text

from .models import AnalysisResult, DebContents, DylibAnalysis, ObjCClass


class ReportGenerator:
    """Generator for analysis reports."""
    
    def __init__(self):
        self.console = Console()
    
    def print_terminal(
        self, 
        deb: DebContents | None, 
        dylib: DylibAnalysis | None,
        verbose: bool = False
    ) -> None:
        """Print analysis results to terminal with colors.
        
        Args:
            deb: Deb contents (optional)
            dylib: Dylib analysis (optional)
            verbose: Whether to show detailed output
        """
        # Print header
        self.console.print(Panel.fit(
            "[bold cyan]iOS Deb Analyzer Report[/bold cyan]",
            border_style="cyan"
        ))
        self.console.print()
        
        # Print package info if available
        if deb:
            self._print_package_info(deb)
        
        # Print dylib analysis if available
        if dylib:
            self._print_dylib_info(dylib, verbose)
    
    def _print_package_info(self, deb: DebContents) -> None:
        """Print package metadata section."""
        self.console.print("[bold yellow]📦 Package Info[/bold yellow]")
        
        meta = deb.metadata
        tree = Tree("")
        
        if meta.name or meta.package:
            tree.add(f"Name: [green]{meta.name or meta.package}[/green]")
        if meta.version:
            tree.add(f"Version: [green]{meta.version}[/green]")
        if meta.author:
            tree.add(f"Author: [green]{meta.author}[/green]")
        if meta.maintainer and meta.maintainer != meta.author:
            tree.add(f"Maintainer: [green]{meta.maintainer}[/green]")
        if meta.architecture:
            tree.add(f"Architecture: [green]{meta.architecture}[/green]")
        if meta.installed_size:
            size_kb = meta.installed_size
            if size_kb >= 1024:
                tree.add(f"Size: [green]{size_kb / 1024:.1f} MB[/green]")
            else:
                tree.add(f"Size: [green]{size_kb} KB[/green]")
        if meta.description:
            tree.add(f"Description: [dim]{meta.description}[/dim]")
        
        # Show target bundle if available
        if deb.plist_filter and "bundles" in deb.plist_filter:
            bundles = deb.plist_filter["bundles"]
            if bundles:
                tree.add(f"Target: [magenta]{', '.join(bundles)}[/magenta]")
        
        self.console.print(tree)
        self.console.print()

    def _print_dylib_info(self, dylib: DylibAnalysis, verbose: bool) -> None:
        """Print dylib analysis section."""
        # Print header info
        self._print_header_info(dylib)
        
        # Print Objective-C classes with methods (hierarchical)
        self._print_objc_classes(dylib)
        
        # Print hooked methods section (highlighted)
        self._print_hooked_methods(dylib)
        
        # Print imported libraries
        self._print_imported_libs(dylib)
        
        # Print exported symbols
        if verbose:
            self._print_exported_symbols(dylib)
            self._print_imported_symbols(dylib)
            self._print_strings(dylib)
    
    def _print_header_info(self, dylib: DylibAnalysis) -> None:
        """Print Mach-O header information."""
        header = dylib.header
        self.console.print("[bold yellow]🔧 Binary Info[/bold yellow]")
        
        tree = Tree("")
        tree.add(f"Architecture: [green]{header.arch}[/green]")
        tree.add(f"Platform: [green]{header.platform}[/green]")
        if header.min_os_version:
            tree.add(f"Min OS Version: [green]{header.min_os_version}[/green]")
        tree.add(f"File Type: [green]{header.file_type}[/green]")
        
        self.console.print(tree)
        self.console.print()
    
    def _print_objc_classes(self, dylib: DylibAnalysis) -> None:
        """Print Objective-C classes with method hierarchy."""
        classes = dylib.objc_classes
        if not classes:
            return
        
        # Check if any class has hooked methods
        hooked_class_names = {cls_name for cls_name, _ in dylib.hooked_methods}
        
        self.console.print(f"[bold yellow]📚 Objective-C Classes ({len(classes)} found)[/bold yellow]")
        
        tree = Tree("")
        for cls in classes:
            # Mark class as hooked if it has hooked methods
            is_hooked_class = cls.name in hooked_class_names or any(m.is_hooked for m in cls.methods)
            
            if is_hooked_class:
                class_node = tree.add(f"[bold red]{cls.name}[/bold red] [red][HOOKED][/red]")
            else:
                class_node = tree.add(f"[cyan]{cls.name}[/cyan]")
            
            # Add methods
            for method in cls.methods:
                prefix = "+" if method.is_class_method else "-"
                method_str = f"{prefix}[{cls.name} {method.name}]"
                
                if method.is_hooked:
                    class_node.add(f"[red]{method_str}[/red] ⚡")
                else:
                    class_node.add(f"[dim]{method_str}[/dim]")
        
        self.console.print(tree)
        self.console.print()
    
    def _print_hooked_methods(self, dylib: DylibAnalysis) -> None:
        """Print hooked methods section with highlighting."""
        hooked = dylib.hooked_methods
        if not hooked:
            return
        
        self.console.print(f"[bold yellow]🔗 Hooked Methods ({len(hooked)} found)[/bold yellow]")
        
        tree = Tree("")
        for cls_name, method_name in hooked:
            tree.add(f"[bold red]-[{cls_name} {method_name}][/bold red]")
        
        self.console.print(tree)
        self.console.print()
    
    def _print_imported_libs(self, dylib: DylibAnalysis) -> None:
        """Print imported libraries."""
        libs = dylib.imported_libs
        if not libs:
            return
        
        self.console.print(f"[bold yellow]📥 Imported Libraries ({len(libs)} found)[/bold yellow]")
        
        tree = Tree("")
        for lib in libs:
            tree.add(f"[green]{lib}[/green]")
        
        self.console.print(tree)
        self.console.print()
    
    def _print_exported_symbols(self, dylib: DylibAnalysis) -> None:
        """Print exported symbols (verbose mode)."""
        symbols = dylib.exported_symbols
        if not symbols:
            return
        
        self.console.print(f"[bold yellow]📤 Exported Symbols ({len(symbols)} found)[/bold yellow]")
        
        tree = Tree("")
        for symbol in symbols[:50]:  # Limit to first 50
            tree.add(f"[dim]{symbol}[/dim]")
        
        if len(symbols) > 50:
            tree.add(f"[dim]... and {len(symbols) - 50} more[/dim]")
        
        self.console.print(tree)
        self.console.print()
    
    def _print_imported_symbols(self, dylib: DylibAnalysis) -> None:
        """Print imported symbols (verbose mode)."""
        symbols = dylib.imported_symbols
        if not symbols:
            return
        
        self.console.print(f"[bold yellow]📥 Imported Symbols ({len(symbols)} found)[/bold yellow]")
        
        tree = Tree("")
        for symbol in symbols[:50]:  # Limit to first 50
            tree.add(f"[dim]{symbol}[/dim]")
        
        if len(symbols) > 50:
            tree.add(f"[dim]... and {len(symbols) - 50} more[/dim]")
        
        self.console.print(tree)
        self.console.print()
    
    def _print_strings(self, dylib: DylibAnalysis) -> None:
        """Print extracted strings (verbose mode)."""
        strings = dylib.strings
        if not strings:
            return
        
        self.console.print(f"[bold yellow]📝 Strings ({len(strings)} found)[/bold yellow]")
        
        tree = Tree("")
        for s in strings[:30]:  # Limit to first 30
            # Truncate long strings
            display = s[:80] + "..." if len(s) > 80 else s
            tree.add(f"[dim]{display}[/dim]")
        
        if len(strings) > 30:
            tree.add(f"[dim]... and {len(strings) - 30} more[/dim]")
        
        self.console.print(tree)
        self.console.print()

    def to_json(
        self, 
        deb: DebContents | None, 
        dylib: DylibAnalysis | None
    ) -> str:
        """Convert analysis results to JSON format.
        
        Args:
            deb: Deb contents (optional)
            dylib: Dylib analysis (optional)
            
        Returns:
            JSON string representation
        """
        result: dict[str, Any] = {}
        
        if deb:
            result["deb_contents"] = self._deb_to_dict(deb)
        
        if dylib:
            result["dylib_analysis"] = self._dylib_to_dict(dylib)
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    def _deb_to_dict(self, deb: DebContents) -> dict[str, Any]:
        """Convert DebContents to dictionary for JSON serialization."""
        return {
            "metadata": {
                "package": deb.metadata.package,
                "name": deb.metadata.name,
                "version": deb.metadata.version,
                "author": deb.metadata.author,
                "maintainer": deb.metadata.maintainer,
                "description": deb.metadata.description,
                "depends": deb.metadata.depends,
                "architecture": deb.metadata.architecture,
                "installed_size": deb.metadata.installed_size,
            },
            "files": deb.files,
            "dylib_paths": deb.dylib_paths,
            "plist_filter": deb.plist_filter,
        }
    
    def _dylib_to_dict(self, dylib: DylibAnalysis) -> dict[str, Any]:
        """Convert DylibAnalysis to dictionary for JSON serialization."""
        return {
            "header": {
                "arch": dylib.header.arch,
                "platform": dylib.header.platform,
                "min_os_version": dylib.header.min_os_version,
                "file_type": dylib.header.file_type,
            },
            "imported_libs": dylib.imported_libs,
            "imported_symbols": dylib.imported_symbols,
            "exported_symbols": dylib.exported_symbols,
            "objc_classes": [
                {
                    "name": cls.name,
                    "superclass": cls.superclass,
                    "methods": [
                        {
                            "name": m.name,
                            "selector": m.selector,
                            "is_class_method": m.is_class_method,
                            "is_hooked": m.is_hooked,
                            "imp_address": hex(m.imp_address) if m.imp_address else None,
                            "imp_offset": hex(m.imp_offset) if m.imp_offset else None,
                        }
                        for m in cls.methods
                    ],
                }
                for cls in dylib.objc_classes
            ],
            "hooked_methods": [
                {"class": cls_name, "method": method_name}
                for cls_name, method_name in dylib.hooked_methods
            ],
            "strings": dylib.strings,
        }
    
    def save_to_file(self, content: str, output_path: Path) -> None:
        """Save content to a file.
        
        Args:
            content: Content to save
            output_path: Path to output file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
    
    def from_json(self, json_str: str) -> tuple[DebContents | None, DylibAnalysis | None]:
        """Parse JSON string back to data objects.
        
        Args:
            json_str: JSON string to parse
            
        Returns:
            Tuple of (DebContents or None, DylibAnalysis or None)
        """
        from .models import DebMetadata, MachOHeader, ObjCClass, ObjCMethod
        
        data = json.loads(json_str)
        
        deb = None
        dylib = None
        
        if "deb_contents" in data:
            deb_data = data["deb_contents"]
            meta_data = deb_data.get("metadata", {})
            metadata = DebMetadata(
                package=meta_data.get("package", ""),
                name=meta_data.get("name", ""),
                version=meta_data.get("version", ""),
                author=meta_data.get("author", ""),
                maintainer=meta_data.get("maintainer", ""),
                description=meta_data.get("description", ""),
                depends=meta_data.get("depends", []),
                architecture=meta_data.get("architecture", ""),
                installed_size=meta_data.get("installed_size", 0),
            )
            deb = DebContents(
                metadata=metadata,
                files=deb_data.get("files", []),
                dylib_paths=deb_data.get("dylib_paths", []),
                plist_filter=deb_data.get("plist_filter"),
            )
        
        if "dylib_analysis" in data:
            dylib_data = data["dylib_analysis"]
            header_data = dylib_data.get("header", {})
            header = MachOHeader(
                arch=header_data.get("arch", ""),
                platform=header_data.get("platform", ""),
                min_os_version=header_data.get("min_os_version", ""),
                file_type=header_data.get("file_type", ""),
            )
            
            objc_classes = []
            for cls_data in dylib_data.get("objc_classes", []):
                methods = [
                    ObjCMethod(
                        name=m.get("name", ""),
                        selector=m.get("selector", ""),
                        is_class_method=m.get("is_class_method", False),
                        is_hooked=m.get("is_hooked", False),
                    )
                    for m in cls_data.get("methods", [])
                ]
                objc_classes.append(ObjCClass(
                    name=cls_data.get("name", ""),
                    superclass=cls_data.get("superclass"),
                    methods=methods,
                ))
            
            hooked_methods = [
                (h.get("class", ""), h.get("method", ""))
                for h in dylib_data.get("hooked_methods", [])
            ]
            
            dylib = DylibAnalysis(
                header=header,
                imported_libs=dylib_data.get("imported_libs", []),
                imported_symbols=dylib_data.get("imported_symbols", []),
                exported_symbols=dylib_data.get("exported_symbols", []),
                objc_classes=objc_classes,
                hooked_methods=hooked_methods,
                strings=dylib_data.get("strings", []),
            )
        
        return deb, dylib
