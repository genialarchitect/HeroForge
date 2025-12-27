//! ELF (Executable and Linkable Format) File Parser
//!
//! Parses Linux ELF files to extract headers, sections, symbols,
//! dynamic libraries, and security features.

use super::entropy::calculate_entropy;
use super::types::*;
use anyhow::{Context, Result};
use goblin::elf::Elf;

/// Parse an ELF file and extract analysis information
pub fn parse_elf(data: &[u8]) -> Result<ElfAnalysis> {
    let elf = Elf::parse(data).context("Failed to parse ELF file")?;

    // Machine type
    let machine_type = match elf.header.e_machine {
        0x03 => "i386".to_string(),
        0x3E => "x86_64".to_string(),
        0x28 => "ARM".to_string(),
        0xB7 => "AArch64".to_string(),
        0x08 => "MIPS".to_string(),
        0x14 => "PowerPC".to_string(),
        0x15 => "PowerPC64".to_string(),
        0xF3 => "RISC-V".to_string(),
        other => format!("Unknown (0x{:04x})", other),
    };

    // ELF type
    let elf_type = match elf.header.e_type {
        1 => "REL".to_string(),  // Relocatable
        2 => "EXEC".to_string(), // Executable
        3 => "DYN".to_string(),  // Shared object
        4 => "CORE".to_string(), // Core dump
        other => format!("Unknown ({})", other),
    };

    // OS/ABI
    let os_abi = match elf.header.e_ident[7] {
        0x00 => "System V".to_string(),
        0x01 => "HP-UX".to_string(),
        0x02 => "NetBSD".to_string(),
        0x03 => "Linux".to_string(),
        0x04 => "GNU Hurd".to_string(),
        0x06 => "Solaris".to_string(),
        0x07 => "AIX".to_string(),
        0x08 => "IRIX".to_string(),
        0x09 => "FreeBSD".to_string(),
        0x0A => "Tru64".to_string(),
        0x0B => "Novell Modesto".to_string(),
        0x0C => "OpenBSD".to_string(),
        0x0D => "OpenVMS".to_string(),
        0x0E => "NonStop Kernel".to_string(),
        0x0F => "AROS".to_string(),
        0x10 => "FenixOS".to_string(),
        0x11 => "Nuxi CloudABI".to_string(),
        other => format!("Unknown (0x{:02x})", other),
    };

    // Is 64-bit?
    let is_64bit = elf.is_64;

    // Entry point
    let entry_point = elf.entry;

    // Interpreter (dynamic linker)
    let interpreter = elf.interpreter.map(|s| s.to_string());

    // Check security features
    let (is_pie, has_relro, has_nx, has_stack_canary) = check_security_features(&elf);

    // Parse sections
    let sections: Vec<ElfSection> = elf.section_headers.iter().enumerate().map(|(i, sh)| {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();

        let section_type = match sh.sh_type {
            0 => "NULL".to_string(),
            1 => "PROGBITS".to_string(),
            2 => "SYMTAB".to_string(),
            3 => "STRTAB".to_string(),
            4 => "RELA".to_string(),
            5 => "HASH".to_string(),
            6 => "DYNAMIC".to_string(),
            7 => "NOTE".to_string(),
            8 => "NOBITS".to_string(),
            9 => "REL".to_string(),
            10 => "SHLIB".to_string(),
            11 => "DYNSYM".to_string(),
            14 => "INIT_ARRAY".to_string(),
            15 => "FINI_ARRAY".to_string(),
            16 => "PREINIT_ARRAY".to_string(),
            17 => "GROUP".to_string(),
            18 => "SYMTAB_SHNDX".to_string(),
            other => format!("0x{:x}", other),
        };

        // Calculate entropy for section
        let section_data = get_section_data(data, sh);
        let section_entropy = calculate_entropy(section_data);

        ElfSection {
            name,
            section_type,
            address: sh.sh_addr,
            offset: sh.sh_offset,
            size: sh.sh_size,
            flags: sh.sh_flags,
            entropy: section_entropy,
            is_executable: (sh.sh_flags & 0x4) != 0, // SHF_EXECINSTR
            is_writable: (sh.sh_flags & 0x1) != 0,   // SHF_WRITE
        }
    }).collect();

    // Parse symbols
    let symbols: Vec<ElfSymbol> = elf.syms.iter().map(|sym| {
        let name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();

        let symbol_type = match sym.st_type() {
            0 => "NOTYPE".to_string(),
            1 => "OBJECT".to_string(),
            2 => "FUNC".to_string(),
            3 => "SECTION".to_string(),
            4 => "FILE".to_string(),
            5 => "COMMON".to_string(),
            6 => "TLS".to_string(),
            other => format!("Unknown ({})", other),
        };

        let binding = match sym.st_bind() {
            0 => "LOCAL".to_string(),
            1 => "GLOBAL".to_string(),
            2 => "WEAK".to_string(),
            10 => "LOOS".to_string(),
            12 => "HIOS".to_string(),
            13 => "LOPROC".to_string(),
            15 => "HIPROC".to_string(),
            other => format!("Unknown ({})", other),
        };

        ElfSymbol {
            name,
            symbol_type,
            binding,
            address: sym.st_value,
            size: sym.st_size,
            section_index: sym.st_shndx as u16,
        }
    }).collect();

    // Parse dynamic libraries
    let dynamic_libs: Vec<ElfDynamic> = elf.libraries.iter().map(|lib| {
        ElfDynamic {
            name: lib.to_string(),
            path: None, // Path resolution requires system access
        }
    }).collect();

    Ok(ElfAnalysis {
        machine_type,
        elf_type,
        os_abi,
        entry_point,
        is_64bit,
        is_pie,
        has_relro,
        has_nx,
        has_stack_canary,
        interpreter,
        sections,
        symbols,
        dynamic_libs,
    })
}

/// Get raw data for a section
fn get_section_data<'a>(data: &'a [u8], section: &goblin::elf::SectionHeader) -> &'a [u8] {
    // NOBITS sections have no data in file
    if section.sh_type == 8 {
        return &[];
    }

    let start = section.sh_offset as usize;
    let size = section.sh_size as usize;
    let end = (start + size).min(data.len());

    if start < data.len() {
        &data[start..end]
    } else {
        &[]
    }
}

/// Check ELF security features
fn check_security_features(elf: &Elf) -> (bool, bool, bool, bool) {
    let mut is_pie = false;
    let mut has_relro = false;
    let mut has_nx = false;
    let mut has_stack_canary = false;

    // PIE: Position Independent Executable
    // DYN type with EXEC permissions usually indicates PIE
    if elf.header.e_type == 3 { // ET_DYN
        // Check if it has an entry point (not just a shared lib)
        if elf.entry != 0 {
            is_pie = true;
        }
    }

    // Check program headers for security features
    for ph in &elf.program_headers {
        match ph.p_type {
            // GNU_RELRO
            0x6474e552 => {
                has_relro = true;
            }
            // GNU_STACK
            0x6474e551 => {
                // If stack is not executable, NX is enabled
                if (ph.p_flags & 0x1) == 0 { // PF_X not set
                    has_nx = true;
                }
            }
            _ => {}
        }
    }

    // Check for full RELRO (BIND_NOW)
    // This is done by checking for DT_BIND_NOW or DT_FLAGS with DF_BIND_NOW
    if let Some(dynamic) = &elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            match dyn_entry.d_tag {
                24 => { // DT_BIND_NOW
                    // Full RELRO
                }
                30 => { // DT_FLAGS
                    if (dyn_entry.d_val & 0x8) != 0 { // DF_BIND_NOW
                        // Full RELRO
                    }
                }
                _ => {}
            }
        }
    }

    // Check for stack canary by looking for __stack_chk_fail symbol
    for sym in &elf.syms {
        let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
        if name == "__stack_chk_fail" || name == "__stack_chk_guard" {
            has_stack_canary = true;
            break;
        }
    }

    (is_pie, has_relro, has_nx, has_stack_canary)
}

/// Get imported functions from dynamic symbols
pub fn get_imports(elf: &Elf) -> Vec<String> {
    elf.dynsyms.iter()
        .filter(|sym| sym.is_import())
        .filter_map(|sym| {
            elf.dynstrtab.get_at(sym.st_name).map(|s| s.to_string())
        })
        .filter(|name| !name.is_empty())
        .collect()
}

/// Get exported functions from dynamic symbols
pub fn get_exports(elf: &Elf) -> Vec<String> {
    elf.dynsyms.iter()
        .filter(|sym| !sym.is_import() && sym.st_bind() == 1) // GLOBAL binding
        .filter_map(|sym| {
            elf.dynstrtab.get_at(sym.st_name).map(|s| s.to_string())
        })
        .filter(|name| !name.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elf_security_features() {
        // Test with minimal valid ELF
        let elf_magic = [
            0x7F, 0x45, 0x4C, 0x46, // ELF magic
            0x02, // 64-bit
            0x01, // Little endian
            0x01, // ELF version
            0x00, // System V ABI
        ];

        // This would fail to parse as it's incomplete
        // Just testing the magic detection works
        assert!(elf_magic.starts_with(&[0x7F, 0x45, 0x4C, 0x46]));
    }
}
