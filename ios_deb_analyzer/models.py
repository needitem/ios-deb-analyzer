"""Data models for iOS Deb Analyzer.

This module defines all data structures used throughout the analyzer.
"""

from dataclasses import dataclass, field
from pathlib import Path


# =============================================================================
# Deb Parser Models
# =============================================================================

@dataclass
class DebMetadata:
    """Metadata extracted from deb control file."""
    package: str = ""
    name: str = ""
    version: str = ""
    author: str = ""
    maintainer: str = ""
    description: str = ""
    depends: list[str] = field(default_factory=list)
    architecture: str = ""
    installed_size: int = 0


@dataclass
class DebContents:
    """Complete contents of a deb package."""
    metadata: DebMetadata
    files: list[str] = field(default_factory=list)  # 설치될 파일 경로 목록
    dylib_paths: list[str] = field(default_factory=list)  # dylib 파일 경로
    plist_filter: dict | None = None  # 타겟 앱 번들 ID


# =============================================================================
# Dylib Analyzer Models
# =============================================================================

@dataclass
class MachOHeader:
    """Mach-O binary header information."""
    arch: str = ""  # arm64, armv7
    platform: str = ""  # iOS
    min_os_version: str = ""
    file_type: str = ""


@dataclass
class ObjCMethod:
    """Objective-C method information."""
    name: str = ""  # 메서드 이름
    selector: str = ""  # 셀렉터
    is_class_method: bool = False  # + or -
    is_hooked: bool = False  # 후킹 여부


@dataclass
class ObjCClass:
    """Objective-C class information."""
    name: str = ""
    methods: list[ObjCMethod] = field(default_factory=list)
    superclass: str | None = None


@dataclass
class DylibAnalysis:
    """Complete analysis result of a dylib binary."""
    header: MachOHeader = field(default_factory=MachOHeader)
    imported_libs: list[str] = field(default_factory=list)
    imported_symbols: list[str] = field(default_factory=list)
    exported_symbols: list[str] = field(default_factory=list)
    objc_classes: list[ObjCClass] = field(default_factory=list)
    hooked_methods: list[tuple[str, str]] = field(default_factory=list)  # (class, method)
    strings: list[str] = field(default_factory=list)


# =============================================================================
# Analysis Result Model
# =============================================================================

@dataclass
class AnalysisResult:
    """Complete analysis result combining deb and dylib analysis."""
    deb_contents: DebContents | None = None
    dylib_analyses: list[DylibAnalysis] = field(default_factory=list)
    analysis_time: float = 0.0


# =============================================================================
# Custom Exceptions
# =============================================================================

class InvalidDebError(Exception):
    """Raised when an invalid deb file is provided."""
    pass


class InvalidMachOError(Exception):
    """Raised when an invalid Mach-O file is provided."""
    pass


class BinaryParseError(Exception):
    """Raised when LIEF fails to parse a binary."""
    pass
