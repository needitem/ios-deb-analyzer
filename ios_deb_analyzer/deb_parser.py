"""Deb package parser module.

This module handles parsing of .deb archives and extracting metadata.
"""

import io
import plistlib
import re
import struct
import tarfile
from pathlib import Path
from typing import BinaryIO

from .models import DebContents, DebMetadata, InvalidDebError


# Deb archive magic bytes
DEB_MAGIC = b"!<arch>\n"
AR_FILE_HEADER_SIZE = 60


class DebParser:
    """Parser for iOS .deb packages."""
    
    def parse(self, deb_path: Path) -> DebContents:
        """Parse a deb file and extract its contents.
        
        Args:
            deb_path: Path to the .deb file
            
        Returns:
            DebContents with metadata and file listings
            
        Raises:
            InvalidDebError: If the file is not a valid deb archive
        """
        deb_path = Path(deb_path)
        if not deb_path.exists():
            raise FileNotFoundError(f"File not found: {deb_path}")
        
        with open(deb_path, "rb") as f:
            return self._parse_deb(f)
    
    def _parse_deb(self, f: BinaryIO) -> DebContents:
        """Parse deb archive from file handle."""
        # Verify magic bytes
        magic = f.read(len(DEB_MAGIC))
        if magic != DEB_MAGIC:
            raise InvalidDebError(
                f"Invalid deb file: expected magic bytes {DEB_MAGIC!r}, got {magic!r}"
            )
        
        # Extract ar archive members
        members = self._extract_ar_members(f)
        
        # Find control and data archives
        control_data = None
        data_data = None
        
        for name, data in members.items():
            if name.startswith("control.tar"):
                control_data = data
            elif name.startswith("data.tar"):
                data_data = data
        
        if control_data is None:
            raise InvalidDebError("Invalid deb file: missing control.tar archive")
        if data_data is None:
            raise InvalidDebError("Invalid deb file: missing data.tar archive")
        
        # Parse control file
        metadata = self._parse_control_archive(control_data)
        
        # Parse data archive for file list and plist filter
        files, dylib_paths, plist_filter = self._parse_data_archive(data_data)
        
        return DebContents(
            metadata=metadata,
            files=files,
            dylib_paths=dylib_paths,
            plist_filter=plist_filter,
        )

    def _extract_ar_members(self, f: BinaryIO) -> dict[str, bytes]:
        """Extract all members from an ar archive.
        
        Args:
            f: File handle positioned after magic bytes
            
        Returns:
            Dictionary mapping member names to their data
        """
        members = {}
        
        while True:
            header = f.read(AR_FILE_HEADER_SIZE)
            if len(header) == 0:
                break
            if len(header) < AR_FILE_HEADER_SIZE:
                raise InvalidDebError("Invalid deb file: truncated ar header")
            
            # Parse ar header
            # Format: name[16] + mtime[12] + uid[6] + gid[6] + mode[8] + size[10] + magic[2]
            name = header[0:16].decode("ascii").strip()
            try:
                size = int(header[48:58].decode("ascii").strip())
            except ValueError:
                raise InvalidDebError("Invalid deb file: invalid ar member size")
            
            # Check ar magic
            ar_magic = header[58:60]
            if ar_magic != b"`\n":
                raise InvalidDebError(
                    f"Invalid deb file: invalid ar member magic {ar_magic!r}"
                )
            
            # Handle extended filenames (starting with /)
            if name.startswith("/"):
                # Skip debian-binary and other special entries
                name = name.rstrip("/")
            
            # Read member data
            data = f.read(size)
            if len(data) < size:
                raise InvalidDebError("Invalid deb file: truncated ar member data")
            
            # Ar members are padded to even byte boundaries
            if size % 2 == 1:
                f.read(1)
            
            members[name] = data
        
        return members
    
    def _parse_control_archive(self, data: bytes) -> DebMetadata:
        """Parse control.tar archive and extract metadata.
        
        Args:
            data: Raw bytes of control.tar (possibly compressed)
            
        Returns:
            DebMetadata with parsed fields
        """
        metadata = DebMetadata()
        
        # Try to open as tar (handles gzip, xz, etc.)
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
                for member in tar.getmembers():
                    if member.name.endswith("/control") or member.name == "./control" or member.name == "control":
                        control_file = tar.extractfile(member)
                        if control_file:
                            metadata = self._parse_control_file(control_file.read().decode("utf-8"))
                            break
        except tarfile.TarError as e:
            raise InvalidDebError(f"Invalid deb file: cannot read control archive: {e}")
        
        return metadata

    def _parse_control_file(self, content: str) -> DebMetadata:
        """Parse control file content into DebMetadata.
        
        Args:
            content: Control file text content
            
        Returns:
            DebMetadata with parsed fields
        """
        metadata = DebMetadata()
        
        # Parse Debian control file format (key: value pairs)
        current_key = None
        current_value = []
        
        for line in content.split("\n"):
            if line.startswith(" ") or line.startswith("\t"):
                # Continuation of previous field
                if current_key:
                    current_value.append(line.strip())
            elif ":" in line:
                # Save previous field
                if current_key:
                    self._set_metadata_field(metadata, current_key, "\n".join(current_value))
                
                # Parse new field
                key, _, value = line.partition(":")
                current_key = key.strip().lower()
                current_value = [value.strip()]
            else:
                # Empty line or other
                if current_key:
                    self._set_metadata_field(metadata, current_key, "\n".join(current_value))
                    current_key = None
                    current_value = []
        
        # Don't forget the last field
        if current_key:
            self._set_metadata_field(metadata, current_key, "\n".join(current_value))
        
        return metadata
    
    def _set_metadata_field(self, metadata: DebMetadata, key: str, value: str) -> None:
        """Set a field on DebMetadata based on key name."""
        if key == "package":
            metadata.package = value
        elif key == "name":
            metadata.name = value
        elif key == "version":
            metadata.version = value
        elif key == "author":
            metadata.author = value
        elif key == "maintainer":
            metadata.maintainer = value
        elif key == "description":
            metadata.description = value
        elif key == "depends":
            # Parse comma-separated dependencies
            metadata.depends = [d.strip() for d in value.split(",") if d.strip()]
        elif key == "architecture":
            metadata.architecture = value
        elif key == "installed-size":
            try:
                metadata.installed_size = int(value)
            except ValueError:
                metadata.installed_size = 0
    
    def _parse_plist_filter(self, data: bytes) -> dict | None:
        """Parse MobileSubstrate plist filter.
        
        Args:
            data: Raw plist data
            
        Returns:
            Dictionary with filter info or None
        """
        try:
            plist = plistlib.loads(data)
            # Extract filter information
            filter_info = {}
            if "Filter" in plist:
                filter_data = plist["Filter"]
                if "Bundles" in filter_data:
                    filter_info["bundles"] = filter_data["Bundles"]
                if "Executables" in filter_data:
                    filter_info["executables"] = filter_data["Executables"]
                if "Classes" in filter_data:
                    filter_info["classes"] = filter_data["Classes"]
            return filter_info if filter_info else None
        except Exception:
            return None

    def _parse_data_archive(self, data: bytes) -> tuple[list[str], list[str], dict | None]:
        """Parse data.tar archive and extract file list.
        
        Args:
            data: Raw bytes of data.tar (possibly compressed)
            
        Returns:
            Tuple of (all files list, dylib paths list, plist_filter dict or None)
        """
        files = []
        dylib_paths = []
        plist_filter = None
        
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        # Normalize path (remove leading ./)
                        path = member.name
                        if path.startswith("./"):
                            path = path[2:]
                        
                        files.append(path)
                        
                        # Identify dylib files
                        if path.endswith(".dylib"):
                            dylib_paths.append(path)
                        
                        # Parse MobileSubstrate plist filter
                        if "MobileSubstrate" in path and path.endswith(".plist"):
                            plist_file = tar.extractfile(member)
                            if plist_file:
                                plist_filter = self._parse_plist_filter(plist_file.read())
        except tarfile.TarError as e:
            raise InvalidDebError(f"Invalid deb file: cannot read data archive: {e}")
        
        return files, dylib_paths, plist_filter
    
    def extract_to(self, deb_path: Path, output_dir: Path) -> Path:
        """Extract deb file contents to a directory.
        
        Args:
            deb_path: Path to the .deb file
            output_dir: Directory to extract to
            
        Returns:
            Path to the extraction directory
        """
        deb_path = Path(deb_path)
        output_dir = Path(output_dir)
        
        if not deb_path.exists():
            raise FileNotFoundError(f"File not found: {deb_path}")
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(deb_path, "rb") as f:
            # Verify magic bytes
            magic = f.read(len(DEB_MAGIC))
            if magic != DEB_MAGIC:
                raise InvalidDebError(
                    f"Invalid deb file: expected magic bytes {DEB_MAGIC!r}, got {magic!r}"
                )
            
            # Extract ar archive members
            members = self._extract_ar_members(f)
            
            # Extract data archive
            for name, data in members.items():
                if name.startswith("data.tar"):
                    try:
                        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
                            tar.extractall(output_dir)
                    except tarfile.TarError as e:
                        raise InvalidDebError(f"Invalid deb file: cannot extract data archive: {e}")
                    break
        
        return output_dir
    
    def serialize_control(self, metadata: DebMetadata) -> str:
        """Serialize DebMetadata back to control file format.
        
        Args:
            metadata: DebMetadata to serialize
            
        Returns:
            Control file content as string
        """
        lines = []
        
        if metadata.package:
            lines.append(f"Package: {metadata.package}")
        if metadata.name:
            lines.append(f"Name: {metadata.name}")
        if metadata.version:
            lines.append(f"Version: {metadata.version}")
        if metadata.author:
            lines.append(f"Author: {metadata.author}")
        if metadata.maintainer:
            lines.append(f"Maintainer: {metadata.maintainer}")
        if metadata.description:
            lines.append(f"Description: {metadata.description}")
        if metadata.depends:
            lines.append(f"Depends: {', '.join(metadata.depends)}")
        if metadata.architecture:
            lines.append(f"Architecture: {metadata.architecture}")
        if metadata.installed_size:
            lines.append(f"Installed-Size: {metadata.installed_size}")
        
        return "\n".join(lines)
