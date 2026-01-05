"""Dylib binary analyzer module.

This module handles analysis of Mach-O dylib binaries using LIEF.
"""

from pathlib import Path
import re

import lief

from .models import (
    DylibAnalysis,
    MachOHeader,
    ObjCClass,
    ObjCMethod,
    InvalidMachOError,
)


# Hooking patterns to detect
HOOK_PATTERNS = [
    r"_logos_orig\$",
    r"_logos_meta\$",
    r"MSHookMessageEx",
    r"_logos_method\$",
]


class DylibAnalyzer:
    """Analyzer for Mach-O dylib binaries."""

    def analyze(self, dylib_path: Path) -> DylibAnalysis:
        """Analyze a dylib file completely.

        Args:
            dylib_path: Path to the dylib file

        Returns:
            DylibAnalysis with all extracted information

        Raises:
            InvalidMachOError: If the file is not a valid Mach-O binary
            FileNotFoundError: If the file does not exist
        """
        if not dylib_path.exists():
            raise FileNotFoundError(f"File not found: {dylib_path}")

        binary = lief.parse(str(dylib_path))
        if binary is None:
            raise InvalidMachOError(f"Invalid Mach-O file: {dylib_path}")

        # Check if it's a Mach-O binary
        if not isinstance(binary, lief.MachO.Binary):
            # Handle FAT binary case
            if isinstance(binary, lief.MachO.FatBinary):
                # Use the first binary (usually arm64)
                binary = binary.at(0)
            else:
                raise InvalidMachOError(
                    f"Not a valid Mach-O binary: {dylib_path}"
                )

        result = DylibAnalysis()
        result.header = self._parse_header(binary)
        result.imported_libs = self._extract_imported_libs(binary)
        result.imported_symbols = self._extract_imported_symbols(binary)
        result.exported_symbols = self._extract_exported_symbols(binary)
        result.objc_classes = self.extract_objc_info(binary)
        result.strings = self._extract_strings(binary)
        result.hooked_methods = self.detect_hooked_methods(binary)

        # Mark hooked methods in ObjC classes
        self._mark_hooked_methods(result)

        return result


    def _parse_header(self, binary: lief.MachO.Binary) -> MachOHeader:
        """Parse Mach-O header information.

        Args:
            binary: LIEF MachO binary object

        Returns:
            MachOHeader with architecture, platform, and version info
        """
        header = MachOHeader()

        # Get architecture using correct LIEF API
        cpu_type = binary.header.cpu_type
        if cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
            header.arch = "arm64"
        elif cpu_type == lief.MachO.Header.CPU_TYPE.ARM:
            header.arch = "armv7"
        elif cpu_type == lief.MachO.Header.CPU_TYPE.X86_64:
            header.arch = "x86_64"
        elif cpu_type == lief.MachO.Header.CPU_TYPE.X86:
            header.arch = "i386"
        else:
            header.arch = str(cpu_type)

        # Get file type using correct LIEF API
        file_type = binary.header.file_type
        if file_type == lief.MachO.Header.FILE_TYPE.DYLIB:
            header.file_type = "dylib"
        elif file_type == lief.MachO.Header.FILE_TYPE.EXECUTE:
            header.file_type = "executable"
        elif file_type == lief.MachO.Header.FILE_TYPE.BUNDLE:
            header.file_type = "bundle"
        else:
            header.file_type = str(file_type)

        # Get platform and minimum OS version from build version or version min commands
        header.platform = "Unknown"
        header.min_os_version = ""

        # Try to get build version command first
        if binary.has_build_version:
            build_version = binary.build_version
            platform = build_version.platform
            if platform == lief.MachO.BuildVersion.PLATFORMS.IOS:
                header.platform = "iOS"
            elif platform == lief.MachO.BuildVersion.PLATFORMS.MACOS:
                header.platform = "macOS"
            elif platform == lief.MachO.BuildVersion.PLATFORMS.TVOS:
                header.platform = "tvOS"
            elif platform == lief.MachO.BuildVersion.PLATFORMS.WATCHOS:
                header.platform = "watchOS"
            else:
                header.platform = str(platform)

            minos = build_version.minos
            header.min_os_version = f"{minos[0]}.{minos[1]}.{minos[2]}"

        # Fallback to version min commands
        elif binary.has_version_min:
            version_min = binary.version_min
            cmd_type = version_min.command
            if cmd_type == lief.MachO.VersionMin.TYPE.VERSION_MIN_IPHONEOS:
                header.platform = "iOS"
            elif cmd_type == lief.MachO.VersionMin.TYPE.VERSION_MIN_MACOSX:
                header.platform = "macOS"
            elif cmd_type == lief.MachO.VersionMin.TYPE.VERSION_MIN_TVOS:
                header.platform = "tvOS"
            elif cmd_type == lief.MachO.VersionMin.TYPE.VERSION_MIN_WATCHOS:
                header.platform = "watchOS"

            version = version_min.version
            header.min_os_version = f"{version[0]}.{version[1]}.{version[2]}"

        return header


    def _extract_imported_libs(self, binary: lief.MachO.Binary) -> list[str]:
        """Extract list of imported libraries.

        Args:
            binary: LIEF MachO binary object

        Returns:
            List of imported library names
        """
        libs = []
        for lib in binary.libraries:
            name = lib.name
            # Extract just the library name from the path
            if "/" in name:
                name = name.split("/")[-1]
            libs.append(name)
        return libs

    def _extract_imported_symbols(self, binary: lief.MachO.Binary) -> list[str]:
        """Extract list of imported symbols.

        Args:
            binary: LIEF MachO binary object

        Returns:
            List of imported symbol names
        """
        symbols = []
        for symbol in binary.imported_symbols:
            symbols.append(symbol.name)
        return symbols

    def _extract_exported_symbols(self, binary: lief.MachO.Binary) -> list[str]:
        """Extract list of exported symbols.

        Args:
            binary: LIEF MachO binary object

        Returns:
            List of exported symbol names
        """
        symbols = []
        for symbol in binary.exported_symbols:
            symbols.append(symbol.name)
        return symbols


    def extract_objc_info(self, binary: lief.MachO.Binary) -> list[ObjCClass]:
        """Extract Objective-C class and method information.

        Args:
            binary: LIEF binary object

        Returns:
            List of ObjCClass objects
        """
        classes = []

        # Try LIEF Extended first (if available)
        objc_metadata = binary.objc_metadata
        if objc_metadata is not None:
            for objc_class in objc_metadata.classes:
                if objc_class.is_meta:
                    continue

                superclass_name = None
                if objc_class.super_class is not None:
                    superclass_name = objc_class.super_class.name

                cls = ObjCClass(
                    name=objc_class.name,
                    superclass=superclass_name,
                    methods=[],
                )

                for method in objc_class.methods:
                    objc_method = ObjCMethod(
                        name=method.name,
                        selector=method.name,
                        is_class_method=not method.is_instance,
                        is_hooked=False,
                    )
                    cls.methods.append(objc_method)

                classes.append(cls)
            
            if classes:
                return classes

        # Fallback to custom parser
        try:
            from .objc_parser import extract_objc_metadata
            
            parsed_classes = extract_objc_metadata(binary)
            for parsed in parsed_classes:
                cls = ObjCClass(
                    name=parsed.name,
                    superclass=parsed.superclass or None,
                    methods=[],
                )
                
                for method in parsed.methods:
                    objc_method = ObjCMethod(
                        name=method.name,
                        selector=method.name,
                        is_class_method=method.is_class_method,
                        is_hooked=False,
                        imp_address=method.imp,
                        imp_offset=method.imp_offset,
                    )
                    cls.methods.append(objc_method)
                
                classes.append(cls)
        except Exception as e:
            # If custom parser fails, return empty list
            pass

        return classes

    def detect_hooked_methods(self, binary: lief.MachO.Binary) -> list[tuple[str, str]]:
        """Detect hooked methods using logos/MSHookMessageEx patterns.

        Args:
            binary: LIEF binary object

        Returns:
            List of (class_name, method_name) tuples for hooked methods
        """
        hooked = []
        hooked_set = set()  # To avoid duplicates

        # Compile patterns
        patterns = [re.compile(p) for p in HOOK_PATTERNS]

        # Check all symbols for hook patterns
        all_symbols = list(binary.symbols)

        for symbol in all_symbols:
            name = symbol.name
            for pattern in patterns:
                if pattern.search(name):
                    # Try to extract class and method from symbol name
                    # logos format: _logos_orig$ClassName$methodName
                    # or _logos_method$ClassName$methodName
                    parts = name.split("$")
                    if len(parts) >= 3:
                        class_name = parts[1]
                        method_name = parts[2]
                        key = (class_name, method_name)
                        if key not in hooked_set:
                            hooked_set.add(key)
                            hooked.append(key)
                    break

        return hooked


    def _extract_strings(self, binary: lief.MachO.Binary) -> list[str]:
        """Extract strings from the binary.

        Args:
            binary: LIEF MachO binary object

        Returns:
            List of extracted strings
        """
        strings = []

        # Get strings from __cstring section
        for section in binary.sections:
            if section.name in ("__cstring", "__objc_methname", "__objc_classname"):
                try:
                    content = bytes(section.content)
                    # Split by null bytes and decode
                    for s in content.split(b"\x00"):
                        if len(s) >= 4:  # Only include strings of reasonable length
                            try:
                                decoded = s.decode("utf-8", errors="ignore")
                                if decoded and decoded.isprintable():
                                    strings.append(decoded)
                            except Exception:
                                pass
                except Exception:
                    pass

        return strings

    def _mark_hooked_methods(self, result: DylibAnalysis) -> None:
        """Mark hooked methods in ObjC classes.

        Args:
            result: DylibAnalysis to update
        """
        hooked_set = set(result.hooked_methods)

        for cls in result.objc_classes:
            for method in cls.methods:
                # Check if this method is hooked
                key = (cls.name, method.name)
                if key in hooked_set:
                    method.is_hooked = True
                # Also check with selector
                key_selector = (cls.name, method.selector)
                if key_selector in hooked_set:
                    method.is_hooked = True
