"""Objective-C metadata parser for Mach-O binaries.

This module parses ObjC metadata directly from Mach-O sections
without requiring LIEF Extended.
"""

import struct
from dataclasses import dataclass, field
from typing import Optional
import lief


@dataclass
class ObjCMethodInfo:
    """Parsed Objective-C method."""
    name: str
    types: str = ""
    imp: int = 0  # Implementation address (virtual address)
    imp_offset: int = 0  # File offset
    is_class_method: bool = False


@dataclass
class ObjCClassInfo:
    """Parsed Objective-C class."""
    name: str
    superclass: str = ""
    methods: list[ObjCMethodInfo] = field(default_factory=list)
    instance_methods: list[ObjCMethodInfo] = field(default_factory=list)
    class_methods: list[ObjCMethodInfo] = field(default_factory=list)


class ObjCMetadataParser:
    """Parser for Objective-C metadata in Mach-O binaries."""

    def __init__(self, binary: lief.MachO.Binary):
        self.binary = binary
        self.is_64bit = binary.header.cpu_type in (
            lief.MachO.Header.CPU_TYPE.ARM64,
            lief.MachO.Header.CPU_TYPE.X86_64,
        )
        self.ptr_size = 8 if self.is_64bit else 4
        self.sections: dict[str, lief.MachO.Section] = {}
        self.section_data: dict[str, bytes] = {}
        
        # Cache sections
        for section in binary.sections:
            self.sections[section.name] = section
            self.section_data[section.name] = bytes(section.content)

    def _read_ptr(self, data: bytes, offset: int) -> int:
        """Read a pointer from data."""
        if self.is_64bit:
            return struct.unpack_from('<Q', data, offset)[0]
        return struct.unpack_from('<I', data, offset)[0]

    def _va_to_file_offset(self, va: int) -> int:
        """Convert virtual address to file offset."""
        for section in self.binary.sections:
            start = section.virtual_address
            end = start + section.size
            if start <= va < end:
                return section.offset + (va - start)
        return 0

    def _va_to_offset(self, va: int) -> tuple[Optional[str], int]:
        """Convert virtual address to section name and offset."""
        for name, section in self.sections.items():
            start = section.virtual_address
            end = start + section.size
            if start <= va < end:
                return name, va - start
        return None, 0

    def _read_string_at_va(self, va: int) -> str:
        """Read null-terminated string at virtual address."""
        if va == 0:
            return ""
        
        section_name, offset = self._va_to_offset(va)
        if section_name is None or section_name not in self.section_data:
            return ""
        
        data = self.section_data[section_name]
        if offset >= len(data):
            return ""
        
        end = data.find(b'\x00', offset)
        if end == -1:
            end = len(data)
        
        try:
            return data[offset:end].decode('utf-8', errors='ignore')
        except Exception:
            return ""


    def _parse_method_list(self, va: int, is_class_method: bool = False) -> list[ObjCMethodInfo]:
        """Parse method_list_t structure."""
        methods = []
        
        if va == 0:
            return methods
        
        # Clear pointer authentication bits for arm64e
        va = va & 0x0000FFFFFFFFFFFF
        
        section_name, offset = self._va_to_offset(va)
        if section_name is None or section_name not in self.section_data:
            return methods
        
        data = self.section_data[section_name]
        if offset + 8 > len(data):
            return methods
        
        # method_list_t: uint32_t entsize_and_flags, uint32_t count
        entsize_and_flags = struct.unpack_from('<I', data, offset)[0]
        count = struct.unpack_from('<I', data, offset + 4)[0]
        
        # entsize is lower bits
        entsize = entsize_and_flags & 0x3FFFFFFF
        is_small = (entsize_and_flags & 0x80000000) != 0
        
        if count > 10000 or count == 0:  # Sanity check
            return methods
        
        method_offset = offset + 8
        
        for i in range(count):
            if is_small:
                # Small method list (relative 32-bit offsets)
                # Each entry: int32_t name_offset, int32_t types_offset, int32_t imp_offset
                if method_offset + 12 > len(data):
                    break
                
                name_rel = struct.unpack_from('<i', data, method_offset)[0]
                imp_rel = struct.unpack_from('<i', data, method_offset + 8)[0]
                
                # The offset is relative to the field itself
                name_field_va = va + (method_offset - offset)
                imp_field_va = va + (method_offset - offset) + 8
                
                # For small methods, name points to a SEL reference which points to the actual string
                name_ref_va = (name_field_va + name_rel) & 0xFFFFFFFFFFFFFFFF
                imp_va = (imp_field_va + imp_rel) & 0xFFFFFFFFFFFFFFFF
                
                # Read the selector reference to get actual name pointer
                ref_section, ref_off = self._va_to_offset(name_ref_va)
                if ref_section and ref_section in self.section_data:
                    ref_data = self.section_data[ref_section]
                    if ref_off + self.ptr_size <= len(ref_data):
                        actual_name_ptr = self._read_ptr(ref_data, ref_off)
                        actual_name_ptr = actual_name_ptr & 0x0000FFFFFFFFFFFF
                        name = self._read_string_at_va(actual_name_ptr)
                    else:
                        name = ""
                else:
                    name = ""
                
                imp_offset = self._va_to_file_offset(imp_va)
                method_offset += 12
            else:
                # Large method list (absolute pointers)
                if method_offset + self.ptr_size * 3 > len(data):
                    break
                
                name_ptr = self._read_ptr(data, method_offset)
                imp_ptr = self._read_ptr(data, method_offset + self.ptr_size * 2)
                
                # Clear pointer auth bits
                name_ptr = name_ptr & 0x0000FFFFFFFFFFFF
                imp_va = imp_ptr & 0x0000FFFFFFFFFFFF
                
                name = self._read_string_at_va(name_ptr)
                imp_offset = self._va_to_file_offset(imp_va)
                
                method_offset += self.ptr_size * 3
            
            if name and len(name) > 1 and not name.startswith('@') and ':' not in name[:2]:
                methods.append(ObjCMethodInfo(
                    name=name,
                    types="",
                    imp=imp_va if 'imp_va' in dir() else 0,
                    imp_offset=imp_offset,
                    is_class_method=is_class_method,
                ))
        
        return methods

    def _parse_class_ro(self, va: int, is_metaclass: bool = False) -> tuple[str, list[ObjCMethodInfo]]:
        """Parse class_ro_t structure."""
        if va == 0:
            return "", []
        
        # Clear pointer auth bits
        va = va & 0x0000FFFFFFFFFFFF
        
        section_name, offset = self._va_to_offset(va)
        if section_name is None or section_name not in self.section_data:
            return "", []
        
        data = self.section_data[section_name]
        
        # class_ro_t structure (64-bit):
        # uint32_t flags, instanceStart, instanceSize
        # uint32_t reserved (64-bit only)
        # ptr ivarLayout, name, baseMethods, baseProtocols, ivars, weakIvarLayout, baseProperties
        
        if self.is_64bit:
            if offset + 72 > len(data):
                return "", []
            
            name_ptr = self._read_ptr(data, offset + 24)
            methods_ptr = self._read_ptr(data, offset + 32)
        else:
            if offset + 48 > len(data):
                return "", []
            
            name_ptr = self._read_ptr(data, offset + 12)
            methods_ptr = self._read_ptr(data, offset + 16)
        
        name_ptr = name_ptr & 0x0000FFFFFFFFFFFF
        methods_ptr = methods_ptr & 0x0000FFFFFFFFFFFF
        
        name = self._read_string_at_va(name_ptr)
        methods = self._parse_method_list(methods_ptr, is_class_method=is_metaclass)
        
        return name, methods


    def _parse_class(self, class_ptr: int) -> Optional[ObjCClassInfo]:
        """Parse objc_class structure."""
        if class_ptr == 0:
            return None
        
        # Clear pointer auth bits
        class_ptr = class_ptr & 0x0000FFFFFFFFFFFF
        
        section_name, offset = self._va_to_offset(class_ptr)
        if section_name is None or section_name not in self.section_data:
            return None
        
        data = self.section_data[section_name]
        
        # objc_class structure:
        # ptr isa, superclass, cache, vtable, data (class_ro_t or class_rw_t)
        
        if self.is_64bit:
            if offset + 40 > len(data):
                return None
            
            isa_ptr = self._read_ptr(data, offset)
            superclass_ptr = self._read_ptr(data, offset + 8)
            data_ptr = self._read_ptr(data, offset + 32)
        else:
            if offset + 20 > len(data):
                return None
            
            isa_ptr = self._read_ptr(data, offset)
            superclass_ptr = self._read_ptr(data, offset + 4)
            data_ptr = self._read_ptr(data, offset + 16)
        
        # Clear FAST_DATA_MASK bits
        data_ptr = data_ptr & 0x00007FFFFFFFFFF8 if self.is_64bit else data_ptr & 0xFFFFFFFC
        
        # Parse class_ro_t for instance methods
        class_name, instance_methods = self._parse_class_ro(data_ptr, is_metaclass=False)
        
        if not class_name:
            return None
        
        # Parse metaclass for class methods
        class_methods = []
        if isa_ptr:
            isa_ptr = isa_ptr & 0x0000FFFFFFFFFFFF
            meta_section, meta_offset = self._va_to_offset(isa_ptr)
            if meta_section and meta_section in self.section_data:
                meta_data = self.section_data[meta_section]
                if self.is_64bit and meta_offset + 40 <= len(meta_data):
                    meta_data_ptr = self._read_ptr(meta_data, meta_offset + 32)
                    meta_data_ptr = meta_data_ptr & 0x00007FFFFFFFFFF8
                    _, class_methods = self._parse_class_ro(meta_data_ptr, is_metaclass=True)
                elif not self.is_64bit and meta_offset + 20 <= len(meta_data):
                    meta_data_ptr = self._read_ptr(meta_data, meta_offset + 16)
                    meta_data_ptr = meta_data_ptr & 0xFFFFFFFC
                    _, class_methods = self._parse_class_ro(meta_data_ptr, is_metaclass=True)
        
        # Get superclass name
        superclass_name = ""
        if superclass_ptr:
            superclass_ptr = superclass_ptr & 0x0000FFFFFFFFFFFF
            # Try to find superclass name from symbols
            for symbol in self.binary.symbols:
                if symbol.value == superclass_ptr:
                    name = symbol.name
                    if name.startswith('_OBJC_CLASS_$_'):
                        superclass_name = name[14:]
                    break
        
        return ObjCClassInfo(
            name=class_name,
            superclass=superclass_name,
            instance_methods=instance_methods,
            class_methods=class_methods,
            methods=instance_methods + class_methods,
        )

    def parse(self) -> list[ObjCClassInfo]:
        """Parse all Objective-C classes from the binary."""
        classes = []
        
        # Get __objc_classlist section
        classlist_section = self.sections.get('__objc_classlist')
        if classlist_section is None:
            return classes
        
        classlist_data = self.section_data.get('__objc_classlist', b'')
        if not classlist_data:
            return classes
        
        # Each entry is a pointer to an objc_class
        num_classes = len(classlist_data) // self.ptr_size
        base_va = classlist_section.virtual_address
        
        for i in range(num_classes):
            class_ptr = self._read_ptr(classlist_data, i * self.ptr_size)
            if class_ptr:
                cls = self._parse_class(class_ptr)
                if cls and cls.name:
                    classes.append(cls)
        
        return classes


def extract_objc_metadata(binary: lief.MachO.Binary) -> list[ObjCClassInfo]:
    """Extract Objective-C metadata from a Mach-O binary.
    
    Args:
        binary: LIEF MachO binary object
        
    Returns:
        List of ObjCClassInfo objects
    """
    parser = ObjCMetadataParser(binary)
    return parser.parse()
