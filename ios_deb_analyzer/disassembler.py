"""Disassembler module using Capstone.

This module provides ARM64 disassembly functionality.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import capstone
import lief


@dataclass
class Instruction:
    """Disassembled instruction."""
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    
    def __str__(self) -> str:
        hex_bytes = ' '.join(f'{b:02X}' for b in self.bytes)
        return f"0x{self.address:08X}:  {hex_bytes:<12}  {self.mnemonic:<8} {self.op_str}"


class Disassembler:
    """ARM64 disassembler for Mach-O binaries."""
    
    def __init__(self, binary: lief.MachO.Binary):
        self.binary = binary
        self.raw_data: Optional[bytes] = None
        
        # Determine architecture
        cpu_type = binary.header.cpu_type
        if cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
            self.md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        elif cpu_type == lief.MachO.Header.CPU_TYPE.ARM:
            self.md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif cpu_type == lief.MachO.Header.CPU_TYPE.X86_64:
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif cpu_type == lief.MachO.Header.CPU_TYPE.X86:
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:
            self.md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        
        self.md.detail = True
    
    def load_file(self, file_path: Path) -> None:
        """Load raw file data for disassembly."""
        with open(file_path, 'rb') as f:
            self.raw_data = f.read()
    
    def disassemble_at_offset(self, file_offset: int, size: int = 256) -> list[Instruction]:
        """Disassemble code at a file offset.
        
        Args:
            file_offset: File offset to start disassembly
            size: Number of bytes to disassemble
            
        Returns:
            List of Instruction objects
        """
        if self.raw_data is None:
            return []
        
        if file_offset >= len(self.raw_data):
            return []
        
        end = min(file_offset + size, len(self.raw_data))
        code = self.raw_data[file_offset:end]
        
        # Calculate virtual address from file offset
        va = self._offset_to_va(file_offset)
        
        instructions = []
        for insn in self.md.disasm(code, va):
            instructions.append(Instruction(
                address=insn.address,
                size=insn.size,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                bytes=bytes(insn.bytes),
            ))
        
        return instructions
    
    def disassemble_at_va(self, va: int, size: int = 256) -> list[Instruction]:
        """Disassemble code at a virtual address.
        
        Args:
            va: Virtual address to start disassembly
            size: Number of bytes to disassemble
            
        Returns:
            List of Instruction objects
        """
        file_offset = self._va_to_offset(va)
        if file_offset == 0:
            return []
        
        return self.disassemble_at_offset(file_offset, size)
    
    def _va_to_offset(self, va: int) -> int:
        """Convert virtual address to file offset."""
        for section in self.binary.sections:
            start = section.virtual_address
            end = start + section.size
            if start <= va < end:
                return section.offset + (va - start)
        return 0
    
    def _offset_to_va(self, offset: int) -> int:
        """Convert file offset to virtual address."""
        for section in self.binary.sections:
            start = section.offset
            end = start + section.size
            if start <= offset < end:
                return section.virtual_address + (offset - start)
        return offset  # Fallback to offset as address


def disassemble_function(binary: lief.MachO.Binary, file_path: Path, 
                         offset: int, size: int = 256) -> str:
    """Disassemble a function and return formatted output.
    
    Args:
        binary: LIEF MachO binary
        file_path: Path to the binary file
        offset: File offset of the function
        size: Number of bytes to disassemble
        
    Returns:
        Formatted disassembly string
    """
    disasm = Disassembler(binary)
    disasm.load_file(file_path)
    
    instructions = disasm.disassemble_at_offset(offset, size)
    
    lines = []
    for insn in instructions:
        lines.append(str(insn))
        
        # Stop at RET instruction (end of function)
        if insn.mnemonic == 'ret':
            break
    
    return '\n'.join(lines)
